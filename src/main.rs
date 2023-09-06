use clap::Parser;
use log::error;
use tokio::time::Instant;

mod log_init;
mod ncm_decoder;

/// 多线程ncm解密器
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// ncm所在目录
    #[arg(short, long, default_value_t=String::from(""))]
    ncm_dir: String,
    /// 文件输出目录
    #[arg(short, long, default_value_t=String::from("music"))]
    out_dir: String,
    /// 线程数量
    #[arg(short, long, default_value_t = 4)]
    threads: u8,
}

fn main() {
    log_init::init_logger_with_default();
    let arg = Args::parse();
    let instant = Instant::now();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(arg.threads as usize)
        .build()
        .unwrap()
        .block_on(async {
            if let Err(e) = ncm_decoder::ncm_decoder_batch(arg.ncm_dir, arg.out_dir).await {
                error!("{}", e);
            }
        });
    println!("累计耗时: {}ms", instant.elapsed().as_millis());
}
