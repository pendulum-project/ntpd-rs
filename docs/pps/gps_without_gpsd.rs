use chrono::{NaiveDate, NaiveTime, NaiveDateTime};
use serialport::SerialPort;
use std::io::{self, BufRead, BufReader};
use std::time::Duration;

fn nmea_time_date_to_unix_timestamp(nmea_time: &str, nmea_date: &str) -> Option<f64> {
    let (hour, minute, second) = parse_nmea_time(nmea_time)?;
    let (day, month, year) = parse_nmea_date(nmea_date)?;

    let naive_date = NaiveDate::from_ymd_opt(2000 + year as i32, month, day)?;
    let naive_time = NaiveTime::from_hms_micro_opt(
        hour,
        minute,
        second.trunc() as u32,
        (second.fract() * 1_000_000.0) as u32,
    )?;

    let naive_datetime = NaiveDateTime::new(naive_date, naive_time);
    let timestamp = naive_datetime.timestamp() as f64 + naive_datetime.timestamp_subsec_micros() as f64 * 1e-6;

    Some(timestamp)
}

fn parse_nmea_time(nmea_time: &str) -> Option<(u32, u32, f64)> {
    let hour: u32 = nmea_time.get(0..2)?.parse().ok()?;
    let minute: u32 = nmea_time.get(2..4)?.parse().ok()?;
    let second: f64 = nmea_time.get(4..10)?.parse().ok()?;
    Some((hour, minute, second))
}

fn parse_nmea_date(nmea_date: &str) -> Option<(u32, u32, u32)> {
    let day: u32 = nmea_date.get(0..2)?.parse().ok()?;
    let month: u32 = nmea_date.get(2..4)?.parse().ok()?;
    let year: u32 = nmea_date.get(4..6)?.parse().ok()?;
    Some((day, month, year))
}

fn process_gnrmc(fields: &[&str], current_date: &mut Option<String>) {
    if is_valid_gnrmc(fields) {
        if let Some(date) = fields.get(9) {
            *current_date = Some(date.to_string());
        }
    }
}

fn is_valid_gnrmc(fields: &[&str]) -> bool {
    fields.len() > 9 && fields[2] == "A"
}

fn process_gngga(fields: &[&str], current_date: &Option<String>) {
    if let Some(time) = fields.get(1) {
        if let Some(date) = current_date {
            if let Some(unix_timestamp) = nmea_time_date_to_unix_timestamp(time, date) {
                print_unix_timestamp(unix_timestamp);
            } else {
                eprintln!("Error: Invalid NMEA time/date format");
            }
        } else {
            eprintln!("Error: Current date is missing for GNGGA processing");
        }
    } else {
        eprintln!("Error: Time field is missing in GNGGA sentence");
    }
}

fn print_unix_timestamp(timestamp: f64) {
    println!("Unix timestamp with fractional seconds: {:.6}", timestamp);
}

fn read_and_process_lines(reader: &mut BufReader<Box<dyn SerialPort>>, current_date: &mut Option<String>) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(_) => {
                let fields: Vec<&str> = line.trim().split(',').collect();
                if line.starts_with("$GNRMC") {
                    process_gnrmc(&fields, current_date);
                } else if line.starts_with("$GNGGA") {
                    process_gngga(&fields, current_date);
                }
            },
            Err(e) => {
                eprintln!("Error reading from serial port: {}", e);
                break;
            }
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let port_name = "/dev/serial0";

    let port = match open_serial_port(port_name, 9600, Duration::from_secs(10)) {
        Ok(port) => port,
        Err(e) => {
            eprintln!("Failed to open port {}: {}", port_name, e);
            return Err(e);
        }
    };
    
    println!("Opened port succesfully: {}", port_name);
    let mut reader = BufReader::new(port);
    let mut current_date = None;

    if let Err(e) = read_and_process_lines(&mut reader, &mut current_date) {
        eprintln!("Error processing lines from serial port: {}", e);
    }

    Ok(())
}

fn open_serial_port(port_name: &str, baud_rate: u32, timeout: Duration) -> io::Result<Box<dyn SerialPort>> {
    match serialport::new(port_name, baud_rate).timeout(timeout).open() {
        Ok(port) => Ok(port),
        Err(e) => {
            eprintln!("Failed to open port {}: {}", port_name, e);
            Err(e.into())
        }
    }
}