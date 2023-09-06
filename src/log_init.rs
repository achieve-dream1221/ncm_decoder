#![allow(dead_code)]
use chrono::Local;
use colored::Colorize;
use log::LevelFilter;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
/// 初始化日志
///
/// # Arguments
///
/// * `log_path`: 日志存放地址
/// * `level`: 日志过滤级别
///
/// returns: ()
///
/// # Examples
///
/// ```
/// init_logger_with_path("log.txt",LevelFilter::Info);
/// ```
pub(crate) fn init_logger_with_path(log_path: impl AsRef<Path>, level: LevelFilter) {
    env_logger::builder()
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] [{}] [{}:{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level().to_string().color(match record.level() {
                    log::Level::Trace => "blue",
                    log::Level::Debug => "cyan",
                    log::Level::Info => "green",
                    log::Level::Warn => "yellow",
                    log::Level::Error => "red",
                }),
                record.target(),
                record.line().unwrap(),
                record.args(),
            )
        })
        .filter_level(level)
        .target(env_logger::Target::Pipe(Box::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(log_path)
                .unwrap(),
        )))
        .init();
}

/// 使用默认值初始化日志,输出到控制台, 日志过滤级别为Info
///
/// returns: ()
///
/// # Examples
///
/// ```
/// init_logger_with_default();
/// ```
pub(crate) fn init_logger_with_default() {
    env_logger::builder().filter_level(LevelFilter::Info).init();
}
