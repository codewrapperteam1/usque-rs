use std::os::unix::io::FromRawFd;

// ... other imports

#[derive(Debug, Parser)]
pub enum Command {
    // ... existing variants
    #[arg(long)]
    NativeTun { tun_fd: Option<i32> },
}

pub fn cmd_nativetun(cmd: Command) {
    let device = match cmd {
        Command::NativeTun { tun_fd: Some(fd) } => {
            // Create tun device from file descriptor
            unsafe { TUN::from_raw_fd(fd) }
        },
        Command::NativeTun { tun_fd: None } => {
            // Normal kernel device creation
            TUN::new()
        },
        // ... handle other commands
    };
    // ... remaining code for the function
