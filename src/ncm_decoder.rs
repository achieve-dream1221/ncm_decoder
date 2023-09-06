#![allow(dead_code)]
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
use regex::Regex;
use serde::Deserialize;
use std::env;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::fs;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
const CORE_KEY: [u8; 16] = hex!("687A4852416D736F356B496E62617857");
const META_KEY: [u8; 16] = hex!("2331346C6A6B5F215C5D2630553C2728");

type Aes128EcbDec = Decryptor<Aes128>;

static CORE_CIPHER: OnceLock<Aes128EcbDec> = OnceLock::new();
static META_CIPHER: OnceLock<Aes128EcbDec> = OnceLock::new();
static REGEX: OnceLock<Regex> = OnceLock::new();

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
    init();
    create_dir(output_dir.as_ref()).await?;
    let count = get_ncm_count(ncm_dir.as_ref()).await?;
    let mut tasks = Vec::with_capacity(count as usize);
    let bar = Arc::new(
        ProgressBar::new(count)
            .with_style(ProgressStyle::with_template(
                "[{elapsed_precise}] {prefix:.bold} {wide_bar:.cyan/blue} {pos}/{len} {msg}",
            )?)
            .with_prefix("decrypted"),
    );
    let mut ncm_files = fs::read_dir(ncm_dir).await?;
    while let Some(ncm_file) = ncm_files.next_entry().await? {
        if !ncm_file.file_name().to_str().unwrap().ends_with(".ncm") {
            continue;
        }
        tasks.push(tokio::spawn(ncm_decoder(
            ncm_file.path(),
            PathBuf::from(output_dir.as_ref()),
            bar.clone(),
        )));
    }
    for task in tasks {
        task.await??;
    }
    bar.finish_with_message("all done");
    Ok(())
}

async fn ncm_decoder<P: AsRef<Path>>(
    ncm_path: P,
    output_dir: PathBuf,
    bar: Arc<ProgressBar>,
) -> Result<()> {
    let mut file = OpenOptions::new().read(true).open(ncm_path).await?;
    let key_box = get_key_box(&mut file).await?;
    let music_info = get_music_info(&mut file).await?;
    decode_ncm(&mut file, &key_box, &music_info, output_dir).await?;
    bar.inc(1);
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
    info!("共有{}个ncm文件", count);
    Ok(count)
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

async fn get_key_box(ncm_f: &mut File) -> Result<[usize; 256]> {
    verify_header(ncm_f).await?;
    let mut key_data = read_data(ncm_f).await?;
    for byte in &mut key_data {
        *byte ^= 0x64;
    }
    let data = &CORE_CIPHER
        .get()
        .expect("cipher is not initialized")
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut key_data)
        .unwrap()[17..];
    let key_length = data.len();
    let mut key_box: [usize; 256] = (0..=255).collect::<Vec<usize>>().try_into().unwrap();
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

async fn get_music_info(ncm_f: &mut File) -> Result<Music> {
    let mut meta_data = read_data(ncm_f).await?;
    for byte in &mut meta_data {
        *byte ^= 0x63;
    }
    let mut meta_data =
        base64ct::Base64::decode_vec(&String::from_utf8(meta_data).unwrap()[22..]).unwrap();
    let meta_data = META_CIPHER
        .get()
        .expect("cipher is not initialized")
        .clone()
        .decrypt_padded_mut::<Pkcs7>(&mut meta_data)
        .map_err(|e| error!("{:?}", e))
        .unwrap();
    let meta_data = &String::from_utf8_lossy(meta_data)[6..].replace(",0", ",\"0\"");
    let meta_data = serde_json::from_str::<Music>(meta_data)
        .map_err(|e| error!("{:?}", e))
        .unwrap();
    Ok(meta_data)
}

async fn decode_ncm(
    ncm_f: &mut File,
    key_box: &[usize; 256],
    music_info: &Music,
    output_dir: impl AsRef<Path>,
) -> Result<()> {
    ncm_f.seek(SeekFrom::Current(9)).await?;
    read_data(ncm_f).await?;
    let name = legalized_file_name(&format!(
        "{}-{}.{}",
        music_info.artist[0][0], music_info.music_name, music_info.format
    ));
    let mut out_f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(output_dir.as_ref().join(&name))
        .await
        .map_err(|_| {
            error!("Unable to open file: {:?}", name);
        })
        .unwrap();
    let mut buffer = [0; 0x8000];
    loop {
        let len = ncm_f.read(&mut buffer).await?;
        if len == 0 {
            break;
        }
        (0..len).for_each(|i| {
            let j = (i + 1) as u8;
            buffer[i] ^= key_box
                [(key_box[j as usize] + key_box[(key_box[j as usize] + j as usize) & 0xff]) & 0xff]
                as u8;
        });
        out_f.write_all(&buffer[..len]).await?;
        out_f.flush().await?;
    }
    // info!("{} is decrypted", music_info.music_name);
    Ok(())
}

fn init() {
    info!("初始化...");
    CORE_CIPHER.get_or_init(|| Aes128EcbDec::new((&CORE_KEY).into()));
    META_CIPHER.get_or_init(|| Aes128EcbDec::new((&META_KEY).into()));
    REGEX.get_or_init(|| Regex::new(r#"[\\/:*?"<>|]"#).unwrap());
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

fn legalized_file_name(name: &str) -> String {
    REGEX
        .get()
        .expect("regex is not initialized")
        .replace_all(name, "")
        .to_string()
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Privilege {
    pub flag: i64,
}
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
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
