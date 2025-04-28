# Cocoon: Static Information Flow Control in Rust
Cocoon is a Rust library that provides types and mechanisms for statically enforcing information flow control in Rust programs. Cocoon is currently intended to prevent programmer errors such as accidentally leaking a "private" value to an untrusted function or other value. Cocoon does not currently address dynamic labels, integrity labels, OS integration, or leaks caused by other means such as side-channel attacks.

## Folder structure
- `benchmark_games`: contains performance benchmarks from [Debian's Computer Language Benchmark Games](https://salsa.debian.org/benchmarksgame-team/benchmarksgame).
- `ifc_examples`: contains examples using the IFC library.
- `ifc_library`: contains all code defining the IFC library.

## Requirements
Cocoon depends on the *nightly* version of Rust.

## Implementation Overview
### Types
Cocoon provides a series of types for programmers to use on secret data. The following table describes each type and its location in the source code.

| Type | Description | Location |
| ---- | ----------- | -------- |
| `Secret<T, L>` | A secrety value of type `T` with secrecy policy `L` where `T` is constrained to be `SecretValueSafe`| `ifc_library/secret_structs/src/secret.rs` |
| `Label_A` | A secrecy label composed of the policies $\{a\}$. The other defined labels are `Label_None`, `Label_B`, `Label_C`, `Label_AB`, `Label_BC`, `Label_ABC` | `ifc_library/secret_structs/src/lattice.rs` |

### Traits
Cocoon provides several traits which constrain the types that are allowable in a `Secret` or a `secret_block` (see below). The following table briefly describes each trait and provides a definition. Each of these traits are defined in `ifc_library/secret_structs/src/secret.rs`. 

| Trait | Description | Definition | Location |
| ----- | ----------- | ---------- | -------- |
| `VisibleSideEffectFree`  | Limits mutably captured values of secret blocks | `(¬(&mut _) ∨ (&mut Secret<_,_>)) ∧ ¬&InvisibleSideEffectFree)` | `ifc_library/secret_structs/src/secret.rs` |
| `SecretValueSafe` | Restricts `T` in `Secret<T, L>` to interior-immutable, block-safe types |  `Immutable ∧ InvisibleSideEffectFree` | `ifc_library/secret_structs/src/secret.rs` |
| `Immutable` | Types without interior mutability | `¬(UnsafeCell<_>) ∧ ¬(&mut _)` | `ifc_library/secret_structs/src/secret.rs` |
| `InvisibleSideEffectFree` | Types that can be used in secret blocks | Implented individually for built-in and application types | `ifc_library/secret_structs/src/secret.rs` |
| `MoreSecretThan` | Enforces a partial order on secrecy labels. For example, `Label_AB` is `MoreSecretThan<Label_A>` | `L1` is `MoreSecretThan<L2>` $\Leftrightarrow$ $L2 \subseteq L1$| `ifc_library/secret_structs/src/lattice.rs` |

### Macros & Functions
Cocoon contains several macros which expands application code using Cocoon to insert compile-time checks to ensure IFC. Specifically, programmers use the `secret_block!` macro when operating on `Secret` values and Cocoon inserts calls to the other functions listed here to ensure IFC compliance. All listed macros and functions are defined in `ifc_library/macros/src/lib.rs`. 

| Macro | Description | 
| ----- | ----------- | 
| `secret_block!(L { e } )` | Defines a lexically-scoped block for operating on `Secret` values where `L` is the ultimate secrecy label that the application code, `e`, evaluates to. | 

| Function | Description | 
| -------- | ----------- |
| `check_expr(e, L)` | Transforms `e` by $\tau(e, T)$ as defined in the paper, Figure 7 | 
| `expand_expr(e, L)` | Transforms `e` by $\tau(e, F)$ as defined in the paper, Figure 7 | 
| `unwrap_secret(e)`, `unwrap_secret_ref(e)`, and `unwrap_secret_ref_mut(e)` | Only callable from within a `secret_block`, returns the value of a `Secret` object
| `wrap_secret(e)` | Creates a new `Secret<_,L>` with value `e` | 

## Examples & Case Studies
This repository provides several examples to demonstrate integration of Cocoon with applications. 

### Motivating Example (Section 2)
Corresponding to section 2 of the paper, this example computes the number of overlapping days of availability on two calendars, belonging to Alice and Bob. In this example, we want to keep whether Alice or Bob is available on a given day secret. 

This example can be found in `ifc_examples/paper_calendar/src/main.rs`. 

### Spotify TUI (Section 5.1)
Spotify TUI is a Spotify client written in Rust that allows an end user to interact with Spotify from a terminal. Spotify TUI is a popular GitHub project with over 12,000 lines of code and 90 contributors. Cocoon is used to protect the client secret, which is similar to a user account password.

The original Spotify TUI code, downloaded from GitHub, is located in `ifc_examples/spotify-tui/spotify-tui-original` while the modified Cocoon version is located in `ifc_examples/spotify-tui/spotify-tui-cocoon`.

### Servo (Section 5.2)
Servo is Mozilla's browswer engine written in Rust [Linux Foundation 2022]. At the time of writing, it is the sixth-most popular Rust project on GitHub and has been influential in the development of Rust. Mozilla's experiences in creating Servo contributed to Rust's early design. In this example, we use Cocoon to protect responses recieved from an origin server following an HTTP request to prevent other origins, such as JavaScript program, from reading the response body.

Due to its size, Servo is not located within this repository. Instructions for accessing the Cocoon-integrated Servo code is located in `ifc_examples/servo/README.md`. 

### Battleship (Section 5.3)
This example demonstrates Cocoon's ability to protect secret values over a communication channel, using the game of Battleship. This example was also used in Jif and JRIF [Kozyri et al. 2016; Myers et al. 2006] and has been converted to Rust and integrated with Cocoon. In this example, the secret information is the placement of each player's ships.

The non-Cocoon and Cocoon versions of Battleship can be found in `ifc_examples/battleship-no-ifc/src/main.rs` and `ifc_examples/battleship/src/main.rs`, respectively.

### Benchmark Games (Section 5.4)
The Computer Language Benchmark Games [Debian benhmarksgame-team 2022] contains nine programs: `binary-trees`, `fannkuch-redux`, `fasta`, `k-nucleotide`, `mandelbrot`, `n-body`, `pidigits`, `regex-redux`, and `spectral-norm`. To assess the peformance impacts of Cocoon, we modified each of these programs to perform all computation inside `secret_block`s. 

These benchmarks and more information on the evaluation can be found in `benchmark_games/`. 

### Millionaires' Problem
The millionaires' problem considers two millionaires, Alice and Bob, who want to determine who is richer, without revealing their wealth. That is, the goal is to determine whether $a \geq b$ without revealing the values of $a$ or $b$. This is an important problem in cryptography and has applications in ecommerce and data mining. 

In this example, we construct a naive solution to the problem. Each millionaire's wealth is protected by a `Secret` and secret blocks are used to iterate over each millionaire to determine the largest wealth. Note that the solution provided here is simple; there are no network communications nor do we implement the well known solutions of private set intersection or oblivious transfer. This example serves to demonstrate how one can operate on `Secret`s with vectors and loops. 

The code for this example is located in `ifc_examples/millionaires/`. 

## Limitations
Cocoon serves as a proof-of-concept for providing strong IFC guarantees for an off-the-shelf mainstream lanaguage. However, there are some drawbacks in its design that limit its practicality. 

### Design Limitations
- Cocoon only supports static labels, not dynamic labels or integrity labels. In section 3 of the paper, we argue that extending Cocoon to support dynamic and integrity lables should be feasible, though it would add run-time overhead.

### Implementation Limitations
In the paper, we describe several limitations to Cocoon's implementation. We also argue why these limitations are not fundamental flaws in design and how Cocoon could potentially add support for these drawbacks to ease the programming burden and reduce restrictions.
- Cocoon does not allow the use of overloaded operators in secret blocks.
- Application types which implement custom destructors are disallowed, though we argue that custom destructors are rare in practice.
- `secret_block`s may not contain macro calls as Cocoon cannot inspect the resulting macro expansion within the secret block and thus cannot certify that it is side effect free.
- Cocoon allowlists some Rust Standard Library functions, allowing side-effect-free code to call them. These calls must be fully qualified.
- Cocoon supports only a small, fixed-size lattice of labels.

## References
- Debian benchmarksgame-team. 2022. _The Computer Language 22.05 Benchmarks Game_. [https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html](https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html). Accessed 2 November 2022.
- Elisavet Kozyri, Owen Arden, Andrew C. Myers, and Fred B. Schneider. 2016. _JRIF: reactive information flow control for Java._ Technical Report 1813–41194. Cornell University Computing and Information Science. [https://ecommons.cornell.edu/handle/1813/41194](https://ecommons.cornell.edu/handle/1813/41194).
- Linux Foundation. 2022. _Servo_ [https://servo.org](https://servo.org)
- Andrew C. Myers, Lantian Zheng, Steve Zdancewic, Stephen Chong, and Nathaniel Nystrom. 2006. _Jif 3.0: Java information flow_. [http://www.cs.cornell.edu/jif](http://www.cs.cornell.edu/jif).
- _Spofity TUI_. 2021. [https://github.com/Rigellute/spotify-tui](https://github.com/Rigelute/spotify-tui).
- Andrew C. Yao. 1982. _Protocols for secure computations_. 23rd Annual Symposium on Foundations of Computer Science (sfcs 1982). pp. 160-164. [doi: 10.1109/SFCS.1982.88](https://www.computer.org/csdl/proceedings-article/focs/1982/542800160/12OmNyUnEJP)