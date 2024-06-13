use chrono::{NaiveDate, NaiveTime, NaiveDateTime};
use std::io::{self, BufRead, BufReader};
use std::time::Duration;
use serialport::SerialPort;


/// Converts NMEA time and date strings to a Unix timestamp.
///
/// # Arguments
///
/// * `nmea_time` - The NMEA time string.
/// * `nmea_date` - The NMEA date string.
///
/// # Returns
///
/// * `Option<f64>` - The corresponding Unix timestamp with fractional seconds, or `None` if the conversion fails.
pub fn nmea_time_date_to_unix_timestamp(nmea_time: &str, nmea_date: &str) -> Option<f64> {
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

/// Parses an NMEA time string into hours, minutes, and seconds.
///
/// # Arguments
///
/// * `nmea_time` - The NMEA time string in the format `HHMMSS` or `HHMMSS.SS`.
///
/// # Returns
///
/// * `Option<(u32, u32, f64)>` - A tuple containing hours, minutes and seconds, or `None` if parsing fails.
pub fn parse_nmea_time(nmea_time: &str) -> Option<(u32, u32, f64)> {
    if nmea_time.len() < 6 {
        return None;
    }

    let hour: u32 = nmea_time.get(0..2)?.parse().ok()?;
    let minute: u32 = nmea_time.get(2..4)?.parse().ok()?;
    let second: f64 = nmea_time.get(4..).unwrap_or("0").parse().ok()?;
    
    Some((hour, minute, second))
}

/// Parses an NMEA date string into day, month, and year.
///
/// # Arguments
///
/// * `nmea_date` - The NMEA date string in the format `DDMMYY`.
///
/// # Returns
///
/// * `Option<(u32, u32, u32)>` - A tuple containing day, month and year, or `None` if parsing fails.
pub fn parse_nmea_date(nmea_date: &str) -> Option<(u32, u32, u32)> {
    if nmea_date.len() < 6 {
        return None;
    }

    let day: u32 = nmea_date.get(0..2)?.parse().ok()?;
    let month: u32 = nmea_date.get(2..4)?.parse().ok()?;
    let year: u32 = nmea_date.get(4..6)?.parse().ok()?;

    Some((day, month, year))
}

/// Processes GNRMC fields to update the current date.
///
/// # Arguments
///
/// * `fields` - The GNRMC fields.
/// * `current_date` - The current date to be updated.
pub fn process_gnrmc(fields: &[&str], current_date: &mut Option<String>) {
    if is_valid_gnrmc(fields) {
        if let Some(date) = fields.get(9) {
            *current_date = Some(date.to_string());
        }
    }
}

/// Checks if GNRMC fields are valid.
///
/// # Arguments
///
/// * `fields` - The GNRMC fields.
///
/// # Returns
///
/// * `bool` - `true` if the fields are valid, otherwise `false`.
pub fn is_valid_gnrmc(fields: &[&str]) -> bool {
    fields.len() > 9 && fields[2] == "A"
}

/// Processes GNGGA fields to print the Unix timestamp.
///
/// # Arguments
///
/// * `fields` - The GNGGA fields.
/// * `current_date` - The current date.
pub fn process_gngga(fields: &[&str], current_date: &Option<String>) {
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

/// Prints a Unix timestamp in a readable format.
///
/// # Arguments
///
/// * `timestamp` - The Unix timestamp to be printed.
pub fn print_unix_timestamp(timestamp: f64) {
    println!("Unix timestamp with fractional seconds: {:.6}", timestamp);
}

/// Reads and processes lines from the serial port.
///
/// # Arguments
///
/// * `reader` - A buffered reader for the serial port.
/// * `current_date` - The current date to be updated.
///
/// # Returns
///
/// * `io::Result<()>` - The result of reading and processing lines.
pub async fn read_and_process_lines(reader: &mut BufReader<Box<dyn SerialPort>>, current_date: &mut Option<String>) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
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

/// The main function to open the serial port and process GPS data.
///
/// # Returns
///
/// * `io::Result<()>` - The result of running the main function.
pub fn main() -> io::Result<()> {
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

/// Opens a serial port with the specified settings.
///
/// # Arguments
///
/// * `port_name` - The name of the serial port.
/// * `baud_rate` - The baud rate for the serial port.
/// * `timeout` - The timeout duration for the serial port.
///
/// # Returns
///
/// * `io::Result<Box<dyn SerialPort>>` - The opened serial port, or an error if opening fails.
pub fn open_serial_port(port_name: &str, baud_rate: u32, timeout: Duration) -> io::Result<Box<dyn SerialPort>> {
    match serialport::new(port_name, baud_rate).timeout(timeout).open() {
        Ok(port) => Ok(port),
        Err(e) => {
            eprintln!("Failed to open port {}: {}", port_name, e);
            Err(e.into())
        }
    }
    
}#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, BufRead, BufReader, Cursor};
    use std::time::Duration;
    use serialport::SerialPort;

    #[test]
    fn test_parse_nmea_time() {
        let result = parse_nmea_time("123519");
        assert_eq!(result, Some((12, 35, 19.0)));

        let result = parse_nmea_time("123519.00");
        assert_eq!(result, Some((12, 35, 19.00)));

        let result = parse_nmea_time("1234");
        assert_eq!(result, None);

        let result = parse_nmea_time("ab3519");
        assert_eq!(result, None);

        let result = parse_nmea_time("12ab19");
        assert_eq!(result, None);

        let result = parse_nmea_time("1235ab");
        assert_eq!(result, None);

        let result = parse_nmea_time("000000");
        assert_eq!(result, Some((0, 0, 0.0)));
    }

    #[test]
    fn test_parse_nmea_date() {
        let result = parse_nmea_date("230394");
        assert_eq!(result, Some((23, 3, 94)));

        let result = parse_nmea_date("2303");
        assert_eq!(result, None);

        let result = parse_nmea_date("ab0394");
        assert_eq!(result, None);

        let result = parse_nmea_date("23ab94");
        assert_eq!(result, None);

        let result = parse_nmea_date("2303ab");
        assert_eq!(result, None);

        let result = parse_nmea_date("010100");
        assert_eq!(result, Some((1, 1, 0)));
    }

    #[test]
    fn test_nmea_time_date_to_unix_timestamp() {
        let result = nmea_time_date_to_unix_timestamp("123519.00", "250320");
        assert_eq!(result, Some(1585139719.00));

        let result = nmea_time_date_to_unix_timestamp("1234", "250320");
        assert_eq!(result, None);

        let result = nmea_time_date_to_unix_timestamp("123519.00", "2503");
        assert_eq!(result, None);

        let result = nmea_time_date_to_unix_timestamp("12ab19.00", "250320");
        assert_eq!(result, None);

        let result = nmea_time_date_to_unix_timestamp("123519.00", "25ab20");
        assert_eq!(result, None);

        let result = nmea_time_date_to_unix_timestamp("000000.00", "010100");
        assert_eq!(result, Some(946684800.00)); 
    }

    #[test]
    fn test_process_gnrmc_with_valid_data() {
        let mut current_date = None;
        let fields = vec!["GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        process_gnrmc(&fields, &mut current_date);
        assert_eq!(current_date, Some("250320".to_string()));
    }

    #[test]
    fn test_process_gnrmc_with_invalid_data() {
        let mut current_date = None;
        let fields = vec!["GNRMC", "123519.00", "V", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        process_gnrmc(&fields, &mut current_date);
        assert_eq!(current_date, None);
    }

    #[test]
    fn test_process_gnrmc_with_insufficient_fields() {
        let mut current_date = None;
        let fields = vec!["GNRMC", "123519.00", "A"];
        process_gnrmc(&fields, &mut current_date);
        assert_eq!(current_date, None);
    }

    #[test]
    fn test_process_gnrmc_updates_current_date() {
        let mut current_date = Some("240320".to_string());
        let fields = vec!["GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        process_gnrmc(&fields, &mut current_date);
        assert_eq!(current_date, Some("250320".to_string()));
    }

    #[test]
    fn test_is_valid_gnrmc_with_valid_data() {
        let fields = vec!["GNRMC", "123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        assert!(is_valid_gnrmc(&fields));
    }

    #[test]
    fn test_is_valid_gnrmc_with_invalid_status() {
        let fields = vec!["GNRMC", "123519.00", "V", "4807.038", "N", "01131.000", "E", "022.4", "084.4", "250320"];
        assert!(!is_valid_gnrmc(&fields));
    }

    #[test]
    fn test_is_valid_gnrmc_with_insufficient_fields() {
        let fields = vec!["GNRMC", "123519.00", "A"];
        assert!(!is_valid_gnrmc(&fields));
    }
}