use std::time;

const QUOTES_LIST: &[&str] = &[
    "You are friend now.",
    "We save each other.",
    "Good. Proud. I am scary space monster. You are leaky space blob.",
    "Amaze. Amaze. Amaze.",
    "Fist my bump.",
    "Friend, question: why you not dead?",
    "Rocky hate Mark.",
    "Adjust orbit while stupid. Good plan.",
    "Not forever. Orbit decay soon. Then we die.",
    "Grumpy. Angry. Stupid. How long since last sleep, question?",
    "Words of encouragement.",
    "You sleep. I watch.",
    "Rocky not fix. Rocky try.",
    "Friendship is... efficient.",
];

fn main() {
    for &quote in QUOTES_LIST.iter().cycle() {
        rocky_says(quote);
        std::thread::sleep(time::Duration::from_secs(5));
    }
}

fn rocky_says(line: &str) {
    clear_screen();
    println!(
        "\x1b[3mDistance from Tau Ceti: {}\x1b[0m",
        std::process::id()
    );
    print!(
        "     ______
(  /        \\  )  \x1b[3m Rocky: {line}\x1b[0m
\\--|        |--/
 /-\\________/-\\
"
    );
}

fn clear_screen() {
    // Source - https://stackoverflow.com/a/34837038
    // Posted by minghan, modified by community. See post 'Timeline' for change history
    // Retrieved 2026-04-18, License - CC BY-SA 4.0
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}
