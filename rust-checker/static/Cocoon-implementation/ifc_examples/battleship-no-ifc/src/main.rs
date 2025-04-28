#![feature(negative_impls)]
#![allow(unused_parens)]
use std::io::Write;

use session_types::*;

mod util;

const GRID_SIZE: usize = 10;

#[derive(Copy, Clone)]
enum CellStatus {
    Unguessed,
    Empty,
    Hit,
}

impl Default for CellStatus {
    fn default() -> Self {
        CellStatus::Empty
    }
}

type Grid<T> = [[T; GRID_SIZE]; GRID_SIZE];

enum Ship {
    Carrier,
    Battleship,
    Cruiser,
    Submarine,
    Destroyer,
}

#[derive(Default)]
struct Player {
    ship_positions: Grid<bool>,

    // A player's guesses are public information.
    guesses: Grid<CellStatus>,
}

struct Placement {
    // 0: vertical, 1: horizontal.
    orientation: usize,
    start_row: usize,
    start_col: usize,
    size: usize,
}

type PlayerA = Rec<
    Send<
        (usize, usize),
        Offer<
            // Case 1: The game is not finished yet.
            Recv<
                // Did the guess hit a ship?
                bool,
                // Receive Player B's guess.
                Recv<(usize, usize), Choose<Send<bool, Var<Z>>, Eps>>,
            >,
            // Case 2: PlayerB conceeds.
            Eps,
        >,
    >,
>;
type PlayerB = Rec<
    Recv<
        (usize, usize),
        Choose<
            // Case 1: Player A did not win yet.
            Send<
                // Did the guess hit a ship?
                bool,
                Send<
                    // Send Player B's guess.
                    (usize, usize),
                    Offer<Recv<bool, Var<Z>>, Eps>,
                >,
            >,
            // Case 2: Player A won.
            Eps,
        >,
    >,
>;

fn main() {
    session_types::connect(
        |chan| {
            let pb = Player::new();
            game_loop_b(pb, chan);
        },
        |chan| {
            let pa = Player::new();
            game_loop_a(pa, chan);
        },
    );
}

fn print_grid(grid: &Grid<CellStatus>) {
    print!(" ");
    for i in 1..=GRID_SIZE {
        print!(" {}", i);
    }
    println!("");

    for (row_index, row) in grid.iter().enumerate() {
        print!(
            "{} ",
            char::from_u32((row_index + 'A' as usize) as u32).unwrap()
        );
        for status in row {
            match status {
                CellStatus::Unguessed => print!(". "),
                CellStatus::Empty => print!("O "),
                CellStatus::Hit => print!("X "),
            };
        }
        println!("");
    }
}

// Guesses are in the format "[a-j] 1-10"
fn read_guess(
    input: &mut dyn std::io::BufRead,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let mut line = String::new();
    input.read_line(&mut line)?;

    let re = regex::Regex::new(r"([a-jA-J]) (\d+)")?;
    if let Some(captures) = re.captures(&line) {
        let row = captures
            .get(1)
            .unwrap()
            .as_str()
            .to_ascii_lowercase()
            .as_bytes()[0] as usize
            - 'a' as usize;
        let col: usize = captures.get(2).unwrap().as_str().parse()?;

        if col > 10 || col == 0 {
            Err("Column not between 1 and 10.".into())
        } else {
            Ok((row, col - 1))
        }
    } else {
        Err("Incorrectly formatted guess.".into())
    }
}

fn is_occupied(grid: &Grid<bool>, row: usize, col: usize) -> bool {
    (&grid[row])[col]
}

fn is_hit(grid: &Grid<CellStatus>, row: usize, col: usize) -> bool {
    let status = (&grid[row])[col];
    match status {
        CellStatus::Hit => true,
        _ => false,
    }
}

fn count_hits(grid: &Grid<CellStatus>) -> usize {
    grid.iter().flatten().into_iter().fold(0, |sum, x| {
        sum + if let CellStatus::Hit = x { 1 } else { 0 }
    })
}

fn did_win(guesses: &Grid<CellStatus>) -> bool {
    const TOTAL_OCCUPIED_SQUARES: usize = 17;
    count_hits(guesses) == TOTAL_OCCUPIED_SQUARES
}

fn legal_placement(grid: &Grid<bool>, placement: &Placement) -> bool {
    let mut r = placement.start_row;
    let mut c = placement.start_col;
    let rend = r + placement.size;
    let cend = c + placement.size;

    let row_step = if placement.orientation == 1usize {
        1
    } else {
        0
    };

    let col_step = 1 - row_step;

    while r < rend && c < cend && !is_occupied(grid, r, c) {
        r += row_step;
        c += col_step;
    }
    return r == rend || c == cend;
}

fn random_maybe_illegal_placement(grid: &Grid<bool>, ship: &Ship) -> Placement {
    let orientation = util::random(2);
    let mut row_limit = GRID_SIZE;
    let mut col_limit = GRID_SIZE;

    if orientation == 1usize {
        row_limit = GRID_SIZE - ship_size(ship);
    } else {
        col_limit = GRID_SIZE - ship_size(ship);
    }

    let row = util::random(row_limit);
    let col = util::random(col_limit);

    Placement {
        orientation,
        start_row: row,
        start_col: col,
        size: ship_size(ship),
    }
}

fn random_placement(grid: &Grid<bool>, ship: &Ship) -> Placement {
    let mut ship_placement: Placement = random_maybe_illegal_placement(grid, ship);
    while !legal_placement(grid, &ship_placement) {
        ship_placement = random_maybe_illegal_placement(grid, ship);
    }
    return ship_placement;
}

fn place_ship(grid: &mut Grid<bool>, placement: &Placement) {
    let row_step = if placement.orientation == 1usize {
        1
    } else {
        0
    };

    let col_step = 1 - row_step;

    let mut row = placement.start_row;
    let mut col = placement.start_col;
    while row < placement.start_row + placement.size && col < placement.start_col + placement.size {
        grid[row][col] = true;
        row += row_step;
        col += col_step;
    }
}

impl Player {
    fn new() -> Player {
        let ships = [
            Ship::Carrier,
            Ship::Battleship,
            Ship::Cruiser,
            Ship::Submarine,
            Ship::Destroyer,
        ];
        let mut ship_positions: Grid<bool> = [[false; GRID_SIZE]; GRID_SIZE];
        for ship in ships {
            let placement = random_placement(&ship_positions, &ship);
            place_ship(&mut ship_positions, &placement);
        }

        Player {
            ship_positions,
            guesses: [[CellStatus::Unguessed; GRID_SIZE]; GRID_SIZE],
        }
    }
}

fn ship_size(ship: &Ship) -> usize {
    match ship {
        Ship::Carrier => 5,
        Ship::Battleship => 4,
        Ship::Cruiser => 3,
        Ship::Submarine => 3,
        Ship::Destroyer => 2,
    }
}

fn game_loop_a(mut player: Player, chan: session_types::Chan<(), PlayerA>) {
    let mut c = chan.enter();
    let mut player_b_guesses = [[CellStatus::Unguessed; GRID_SIZE]; GRID_SIZE];

    loop {
        println!("Player A's guesses:");
        print_grid(&player.guesses);

        print!("Player A> ");
        std::io::stdout().flush().expect("IO error.");

        let guess = read_guess(&mut std::io::stdin().lock()).expect("Problem reading guess.");

        let c1 = c.send(guess);
        let c2 = match c1.offer() {
            Left(l) => {
                let (c2, did_hit) = l.recv();
                if did_hit {
                    player.guesses[guess.0][guess.1] = CellStatus::Hit;
                } else {
                    player.guesses[guess.0][guess.1] = CellStatus::Empty;
                }

                c2
            }
            Right(r) => {
                // We won on that guess.
                r.close();
                return;
            }
        };

        let (c3, guess) = c2.recv();

        let is_hit: bool = is_occupied(&player.ship_positions, guess.0, guess.1);

        if is_hit {
            println!("Hit!");
            player_b_guesses[guess.0][guess.1] = CellStatus::Hit;
        } else {
            println!("Miss!");
            player_b_guesses[guess.0][guess.1] = CellStatus::Empty;
        }

        if !did_win(&player_b_guesses) {
            c = c3.sel1().send(is_hit).zero();
        } else {
            println!("Player B wins.");
            c3.sel2().close();
            return;
        }
    }
}

fn game_loop_b(mut player: Player, chan: session_types::Chan<(), PlayerB>) {
    let mut c = chan.enter();
    let mut player_a_guesses = [[CellStatus::Unguessed; GRID_SIZE]; GRID_SIZE];

    loop {
        let (c1, guess) = c.recv();

        let is_hit: bool = is_occupied(&player.ship_positions, guess.0, guess.1);
        if is_hit {
            println!("Hit!");
            player_a_guesses[guess.0][guess.1] = CellStatus::Hit;
        } else {
            println!("Miss!");
            player_a_guesses[guess.0][guess.1] = CellStatus::Empty;
        }

        if did_win(&player_a_guesses) {
            println!("Player A wins.");
            c1.sel2().close();
            return;
        }

        let c1 = c1.sel1().send(is_hit);

        println!("Player B's guesses:");
        print_grid(&player.guesses);

        print!("Player B> ");
        std::io::stdout().flush().expect("IO error");

        let guess = read_guess(&mut std::io::stdin().lock()).expect("Unable to read guess.");

        let c1 = c1.send(guess);
        match c1.offer() {
            Left(l) => {
                let (c2, did_hit) = l.recv();
                if did_hit {
                    player.guesses[guess.0][guess.1] = CellStatus::Hit;
                } else {
                    player.guesses[guess.0][guess.1] = CellStatus::Empty;
                }
                c = c2.zero();
            }
            Right(r) => {
                // That was a winning guess.
                r.close();
                return;
            }
        }
    }
}
