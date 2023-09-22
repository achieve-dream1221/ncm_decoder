use aes::cipher::block_padding::Pkcs7;
use aes::cipher::KeyInit;
use aes::Aes128;
use anyhow::{bail, Result};
use base64ct::Encoding;
use ecb::cipher::BlockDecryptMut;
use ecb::Decryptor;
use hex_literal::hex;
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::env;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::task::JoinHandle;

type Aes128EcbDec = Decryptor<Aes128>;

static CORE_CIPHER: Lazy<Aes128EcbDec> =
    Lazy::new(|| Aes128EcbDec::new((&hex!("687A4852416D736F356B496E62617857")).into()));
static META_CIPHER: Lazy<Aes128EcbDec> =
    Lazy::new(|| Aes128EcbDec::new((&hex!("2331346C6A6B5F215C5D2630553C2728")).into()));
static KEY_BOX: Lazy<[usize; 256]> =
    Lazy::new(|| (0..=255).collect::<Vec<usize>>().try_into().unwrap());

static BAR: Lazy<ProgressBar> = Lazy::new(|| {
    let bar = ProgressBar::new(0);
    bar.with_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {prefix:.bold} {wide_bar:.cyan/blue} {pos}/{len} {msg}",
        )
        .unwrap(),
    )
    .with_prefix("decrypted")
});

/// 异步批处理ncm文件
///
/// # Arguments
///
/// * `ncm_dir`: ncm文件夹
/// * `output_dir`: 输出文件夹
///
/// returns: Result<(), Error>
///
/// # Examples
///
/// ```
/// ncm_decoder_batch("D:\\ncm", "D:\\mp3").await?;
/// ```
pub async fn ncm_decoder_batch<P: AsRef<Path>>(ncm_dir: P, output_dir: P) -> Result<()> {
    create_dir(output_dir.as_ref()).await?;
    let count = get_ncm_count(ncm_dir.as_ref()).await?;
    BAR.set_length(count);
    let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::with_capacity(count as usize);
    let mut ncm_files = fs::read_dir(ncm_dir).await?;
    while let Some(ncm_file) = ncm_files.next_entry().await? {
        if !ncm_file.file_name().to_str().unwrap().ends_with(".ncm") {
            continue;
        }
        tasks.push(tokio::spawn(ncm_decoder(
            ncm_file.path(),
            PathBuf::from(output_dir.as_ref()),
        )));
    }
    for task in tasks {
        task.await??;
    }
    BAR.finish_with_message("success!");
    Ok(())
}

pub async fn ncm_decoder<P: AsRef<Path>>(ncm_path: P, output_dir: P) -> Result<()> {
    let ncm_path = ncm_path.as_ref();
    let mut file = OpenOptions::new().read(true).open(ncm_path).await?;
    let key_box = get_key_box(&mut file).await?;
    let format = get_music_format(&mut file).await?;
    decode_ncm(
        &mut file,
        ncm_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace("ncm", format.as_str())
            .as_ref(),
        &key_box,
        output_dir,
    )
    .await?;
    Ok(())
}

async fn get_ncm_count(ncm_dir: impl AsRef<Path>) -> Result<u64> {
    let mut ncm_files = fs::read_dir(ncm_dir).await?;
    let mut count = 0;
    while let Some(ncm_file) = ncm_files.next_entry().await? {
        if ncm_file.file_name().to_str().unwrap().ends_with(".ncm") {
            count += 1;
        }
    }
    // info!("共有{}个ncm文件", count);
    Ok(count)
}

async fn get_key_box(ncm_f: &mut File) -> Result<[usize; 256]> {
    verify_header(ncm_f).await?;
    let mut key_data = read_data(ncm_f).await?;
    key_data.iter_mut().for_each(|byte| *byte ^= 0x64);
    let data: &[u8] = &CORE_CIPHER
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut key_data)
        .unwrap()[17..];
    let key_length = data.len();
    let mut key_box = *KEY_BOX;
    let (mut c, mut last_byte, mut offset, mut swap) = (0, 0, 0, 0);
    (0..=255).for_each(|i| {
        swap = key_box[i];
        c = (swap + last_byte + data[offset] as usize) & 0xff;
        offset += 1;
        if offset >= key_length {
            offset = 0;
        }
        key_box[i] = key_box[c];
        key_box[c] = swap;
        last_byte = c;
    });
    Ok(key_box)
}

async fn get_music_format(ncm_f: &mut File) -> Result<String> {
    let mut meta_data = read_data(ncm_f).await?;
    meta_data.iter_mut().for_each(|byte| *byte ^= 0x63);
    let mut meta_data =
        base64ct::Base64::decode_vec(&String::from_utf8(meta_data).unwrap()[22..]).unwrap();
    let meta_data = META_CIPHER
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut meta_data)
        .map_err(|e| error!("{:?}", e))
        .unwrap();
    // 部分meta数据存在不正确的0类型, 统一替换了同一类型
    let meta_data = String::from_utf8_lossy(meta_data)[6..].replace(",0", ",\"0\"");
    let meta_data = serde_json::from_str::<Music>(&meta_data)?;
    // let data: Value = serde_json::from_str(&meta_data).unwrap();
    Ok(meta_data.format)
}

async fn decode_ncm(
    ncm_f: &mut File,
    name: &str,
    key_box: &[usize; 256],
    output_dir: impl AsRef<Path>,
) -> Result<()> {
    ncm_f.seek(SeekFrom::Current(9)).await?;
    read_data(ncm_f).await?;
    let out_f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(output_dir.as_ref().join(name))
        .await
        .map_err(|_| {
            error!("Unable to open file: {:?}", name);
        })
        .unwrap();
    let mut bw = BufWriter::new(out_f);
    let mut br = BufReader::new(ncm_f);
    let mut buffer = [0; 0x8000];
    while let Ok(len) = br.read(&mut buffer).await {
        if len == 0 {
            break;
        }
        for (i, item) in buffer[..len].iter_mut().enumerate() {
            let j = (i + 1) as u8;
            *item ^= key_box
                [(key_box[j as usize] + key_box[(key_box[j as usize] + j as usize) & 0xff]) & 0xff]
                as u8;
        }
        bw.write_all(&buffer[..len]).await?;
        bw.flush().await?;
    }
    BAR.inc(1);
    Ok(())
}

async fn verify_header(ncm_f: &mut File) -> Result<()> {
    let mut header = [0; 8];
    if let Err(e) = ncm_f.read_exact(&mut header).await {
        bail!("Unable to read header: {}", e)
    }
    assert_eq!(hex::encode(header), "4354454e4644414d");
    ncm_f.seek(SeekFrom::Current(2)).await?;
    Ok(())
}
async fn read_data(ncm_f: &mut File) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    if let Err(e) = ncm_f.read_exact(&mut length).await {
        bail!("Unable to read length: {}", e)
    }
    let mut data = vec![0; u32::from_le_bytes(length) as usize];
    if let Err(e) = ncm_f.read_exact(&mut data).await {
        bail!("Unable to read data: {}", e)
    }
    Ok(data)
}

async fn create_dir<P: AsRef<Path>>(dir: P) -> Result<()> {
    let path = dir.as_ref();
    let path = if path.is_relative() {
        env::current_dir()?.join(path)
    } else {
        path.to_path_buf()
    };
    if !path.exists() {
        fs::create_dir_all(dir).await?;
    }
    info!("文件将保存至: {:?}", path);
    Ok(())
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Privilege {
    pub flag: i64,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Music {
    #[serde(rename = "musicId")]
    pub music_id: String,
    #[serde(rename = "musicName")]
    pub music_name: String,
    pub artist: Vec<Vec<String>>,
    #[serde(rename = "albumId")]
    pub album_id: String,
    pub album: String,
    #[serde(rename = "albumPicDocId")]
    pub album_pic_doc_id: String,
    #[serde(rename = "albumPic")]
    pub album_pic: String,
    pub bitrate: i64,
    #[serde(rename = "mp3DocId")]
    pub mp3doc_id: String,
    pub duration: i64,
    #[serde(rename = "mvId")]
    pub mv_id: String,
    #[serde(rename = "transNames")]
    pub trans_names: Vec<String>,
    pub format: String,
    pub fee: i64,
    pub privilege: Privilege,
}
