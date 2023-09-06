use aes::cipher::block_padding::Pkcs7;
use aes::cipher::KeyInit;
use aes::Aes128;
use base64ct::Encoding;
use ecb::cipher::BlockDecryptMut;
use ecb::Decryptor;
use hex_literal::hex;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

const CORE_KEY: [u8; 16] = hex!("687A4852416D736F356B496E62617857");
const META_KEY: [u8; 16] = hex!("2331346C6A6B5F215C5D2630553C2728");

type Aes128EcbDec = Decryptor<Aes128>;

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

fn ncm2mp3() {
    let mut file = OpenOptions::new().read(true).open("data/ylx.ncm").unwrap();
    let mut header = [0; 8];
    file.read_exact(&mut header).expect("Unable to read header");
    assert_eq!(hex::encode(header), "4354454e4644414d");
    file.seek(SeekFrom::Current(2)).expect("Failed to seek");
    let mut key_length = [0; 4];
    file.read_exact(&mut key_length)
        .expect("Unable to read key length");
    let key_length = u32::from_le_bytes(key_length);
    let mut key_data = vec![0; key_length as usize];
    file.read_exact(&mut key_data).expect("Unable to read key");
    for byte in &mut key_data {
        *byte ^= 0x64;
    }
    let cipher = Aes128EcbDec::new((&CORE_KEY).into());
    let data = &cipher
        .decrypt_padded_mut::<Pkcs7>(&mut key_data)
        .expect("Unable to decrypt key")[17..];
    let key_length = data.len();
    let mut key_box: [usize; 256] = (0..=255).collect::<Vec<usize>>().try_into().unwrap();
    let mut c: usize = 0;
    let mut last_byte: usize = 0;
    let mut offset = 0;
    let mut swap: usize = 0;
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
    let mut meta_length = [0; 4];
    file.read_exact(&mut meta_length)
        .expect("Unable to read key length");
    let meta_length = u32::from_le_bytes(meta_length);
    let mut meta_data = vec![0; meta_length as usize];
    file.read_exact(&mut meta_data).expect("Unable to read key");
    for byte in &mut meta_data {
        *byte ^= 0x63;
    }
    let mut meta_data =
        base64ct::Base64::decode_vec(&String::from_utf8(meta_data).unwrap()[22..]).unwrap();
    let cipher = Aes128EcbDec::new((&META_KEY).into());
    let meta_data = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut meta_data)
        .expect("Unable to decrypt meta");
    let music_info: Music = serde_json::from_str(&String::from_utf8_lossy(meta_data)[6..]).unwrap();
    file.seek(SeekFrom::Current(9)).unwrap();
    let mut image_size = [0; 4];
    file.read_exact(&mut image_size)
        .expect("Unable to read key length");
    let image_size = u32::from_le_bytes(image_size);
    let mut image_data = vec![0; image_size as usize];
    file.read_exact(&mut image_data)
        .expect("Unable to read key");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!(
            "data/{}.{}",
            music_info.music_name, music_info.format
        ))
        .unwrap();
    let mut buffer = [0; 0x8000];
    loop {
        let len = file.read(&mut buffer).unwrap();
        if len == 0 {
            break;
        }
        (0..len).for_each(|i| {
            let j = (i + 1) as u8;
            buffer[i] ^= key_box
                [(key_box[j as usize] + key_box[(key_box[j as usize] + j as usize) & 0xff]) & 0xff]
                as u8;
        });
        f.write_all(&buffer[..len]).unwrap();
        f.flush().unwrap();
    }
}

fn main() {
    ncm2mp3();
}
