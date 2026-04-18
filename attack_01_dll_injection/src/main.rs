use common::find_pid_by_name;

fn main() {
    match find_pid_by_name("victim.exe") {
        Some(pid) => {
            println!("Victim located at coordinate: {}", pid);
        }
        None => {
            println!("Couldn't locate the victim");
        }
    }
}
