use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use console::{style, Term};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;

pub struct StdoutWrap {
    pub stdout: io::Stdout,
}

impl Write for StdoutWrap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match String::from_utf8(buf.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "the plain data is not utf-8 encoded (maybe a binary file), please use file or pipe",
                ))
            }
        };
        self.stdout.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()
    }
}

struct ProgressWrapper {
    desc: String,
    done_desc: String,
    desc_size: usize,

    last_report: Instant,

    current: usize,
    total: usize,

    start: Instant,

    done: bool,
}

impl ProgressWrapper {
    const SPACE: &'static str = " ";
    const SPACE_SIZE: usize = 1;

    const REPORT_INTERVAL: Duration = Duration::from_millis(200);

    pub fn new(desc: String, done_desc: String, total: usize) -> ProgressWrapper {
        let desc_size = console::measure_text_width(&desc);
        let last_report = Instant::now();

        let pw = ProgressWrapper {
            desc,
            done_desc,
            desc_size,
            last_report,
            current: 0,
            total,
            start: Instant::now(),
            done: false,
        };
        eprintln!("{}", pw.render());
        pw
    }

    fn render(&self) -> String {
        let term_size = size();
        if self.desc_size > term_size {
            return ".".repeat(term_size);
        }

        let mut line = self.desc.clone();
        if self.desc_size + Self::SPACE_SIZE > term_size || bar_size() == 0 {
            return line;
        }
        line.push_str(Self::SPACE);

        let bar = render_bar(self.current, self.total);
        let bar_size = console::measure_text_width(&bar);
        let line_size = console::measure_text_width(&line);
        if line_size + bar_size > term_size {
            return line;
        }
        line.push_str(&bar);

        let line_size = console::measure_text_width(&line);
        if line_size + Self::SPACE_SIZE > term_size {
            return line;
        }
        line.push_str(Self::SPACE);

        let info = human_bytes(self.current as u64);
        let info_size = console::measure_text_width(&info);
        let line_size = console::measure_text_width(&line);
        if line_size + info_size > term_size {
            return line;
        }
        line.push_str(&info);

        let line_size = console::measure_text_width(&line);
        if line_size + Self::SPACE_SIZE > term_size {
            return line;
        }
        let elapsed_seconds = self.start.elapsed().as_secs_f64();
        if elapsed_seconds == 0.0 {
            return line;
        }

        line.push_str(Self::SPACE);

        let speed = self.current as f64 / elapsed_seconds;
        let speed = format!("- {}/s", human_bytes(speed as u64));
        let speed_size = console::measure_text_width(&speed);
        let line_size = console::measure_text_width(&line);
        if line_size + speed_size > term_size {
            return line;
        }
        line.push_str(&speed);

        line
    }

    fn update_current(&mut self, size: usize) {
        if self.done {
            return;
        }
        self.current += size;

        if self.current >= self.total {
            self.done = true;
            self.current = self.total;
            cursor_up();
            eprintln!("{} {}", self.done_desc, style("done").green());
            return;
        }

        let now = Instant::now();
        let delta = now - self.last_report;
        if delta >= Self::REPORT_INTERVAL {
            cursor_up();
            eprintln!("{}", self.render());
            self.last_report = now;
        }
    }
}

impl Drop for ProgressWrapper {
    fn drop(&mut self) {
        if self.done || self.current >= self.total {
            return;
        }
        // The progress didn't stop normally, mark it as failed.
        cursor_up();
        eprintln!("{} {}", self.done_desc, style("failed").red());
    }
}

pub struct ProgressReader<R: Read> {
    upstream: R,
    wrapper: ProgressWrapper,
}

impl<R: Read> ProgressReader<R> {
    pub fn new(
        desc: impl ToString,
        done_desc: impl ToString,
        total: usize,
        upstream: R,
    ) -> ProgressReader<R> {
        ProgressReader {
            upstream,
            wrapper: ProgressWrapper::new(desc.to_string(), done_desc.to_string(), total),
        }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.upstream.read(buf)?;
        self.wrapper.update_current(size);

        Ok(size)
    }
}

fn cursor_up() {
    const CURSOR_UP_CHARS: &str = "\x1b[A\x1b[K";
    eprint!("{CURSOR_UP_CHARS}");
}

/// Return the current terminal width size.
fn size() -> usize {
    let term = Term::stdout();
    let (_, col_size) = term.size();
    col_size as usize
}

fn bar_size() -> usize {
    let term_size = size();
    if term_size <= 20 {
        0
    } else {
        term_size / 4
    }
}

/// Render the progress bar.
fn render_bar(current: usize, total: usize) -> String {
    let bar_size = bar_size();
    let current_count = if current >= total {
        bar_size
    } else {
        let percent = (current as f64) / (total as f64);
        let current_f64 = (bar_size as f64) * percent;
        let current = current_f64 as u64 as usize;
        if current >= bar_size {
            bar_size
        } else {
            current
        }
    };
    let current = match current_count {
        0 => String::new(),
        1 => String::from(">"),
        _ => format!("{}>", "=".repeat(current_count - 1)),
    };
    if current_count >= bar_size {
        return format!("[{current}]");
    }

    let pending = " ".repeat(bar_size - current_count);
    format!("[{current}{pending}]")
}

/// Convert a size to a human-readable string, for example, "32KB".
pub fn human_bytes<T: Into<u64>>(bytes: T) -> String {
    const BYTES_UNIT: f64 = 1024.0;
    const BYTES_SUFFIX: [&str; 9] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
    let size = bytes.into();
    let size = size as f64;
    if size <= 0.0 {
        return String::from("0 B");
    }

    let base = size.log10() / BYTES_UNIT.log10();
    let result = format!("{:.1}", BYTES_UNIT.powf(base - base.floor()))
        .trim_end_matches(".0")
        .to_owned();

    [&result, BYTES_SUFFIX[base.floor() as usize]].join(" ")
}

pub fn input_password(user: &str, confirm: bool) -> Result<String> {
    let msg = format!(
        "{} Input password for {user:?}: ",
        style("::").bold().magenta()
    );
    let password = rpassword::prompt_password(msg).context("input password from tty")?;
    if password.is_empty() {
        bail!("password can't be empty");
    }

    if confirm {
        let msg = format!("{} Confirm password: ", style("::").bold().magenta());
        let confirm = rpassword::prompt_password(msg).context("confirm password from tty")?;
        if password != confirm {
            bail!("passwords do not match");
        }
    }

    Ok(password)
}

pub fn input_user() -> Result<String> {
    let theme = ColorfulTheme::default();
    let input: Input<String> = Input::with_theme(&theme).with_prompt("Input user");
    let user = input.interact_text().context("terminal input")?;
    if user.is_empty() {
        bail!("user cannot be empty");
    }
    Ok(user)
}
