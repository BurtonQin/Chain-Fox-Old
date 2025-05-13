<div align="center">
  <img src="https://www.chain-fox.com/logo.png" width="128" height="128">
  <h1>Chain-Fox</h1>
  <p>Bringing automated analysis to blockchain security.</p>

  [![Website](https://img.shields.io/badge/Website-Chain--Fox-blue)](https://chain-fox.com)
  [![Discord](https://img.shields.io/badge/Discord-Join-7289DA)](https://discord.gg/9Eyut3GJ)
  [![Telegram](https://img.shields.io/badge/Telegram-Join-26A5E4)](https://t.me/chainfox_sol)
  [![X](https://img.shields.io/badge/X-Follow-black)](https://x.com/ChainFoxHQ)

  **CA:** `RhFVq1Zt81VvcoSEMSyCGZZv5SwBdA8MV7w4HEMpump`
</div>

## 🎯 Why Chain-Fox

Security is the biggest concern for blockchain and smart contract users and developers.
But a manual audit is time-consuming and expensive.
Thus we establish **Chain-Fox**, 
an *all-in-one* platform with automatic security detection ability, making the security capabilities of blockchain more democratic. 
We aim to make security *affordable* to every user and developer in the blockchain ecosystem.

## 🔍 Checkers Supported

Checkers can be divided by languages and detection methods.

For now we are supporting 14 cutting-edge checkers. Deploying them to your working CI is non-trivial. We also have other 8 checkers that are easily integrated into CI. For these 8 checkers, a sophisticated guide of deploying them is coming soon.

According to a recent survey, most blockchain-related projects are implemented in Rust, Go, Solidity, and C++. Thus we focus on these languages. Besides them, more recent languages (like Move) are to be added.

We are also planning to add more checkers see [here](https://github.com/Chain-Fox/Awesome-Rust-Checker).

| Checker | Categories | Detected Bug Types |
| ------- | ---------- | --------|
| lockbud | rust, static | Memory & Concurrency bugs
| rudra   | rust, static |  Memory safety when panicked, Higher Order Invariant, Send Sync Variance, Lifetime Annotation Bugs |
| RAPx | rust, static | Use-After-Free, Double-Free, Memory Leaks | 
| AtomVChecker | rust, static | Atomic concurrency bugs and performance loss due to memory ordering misuse |
| Cocoon | rust, static | Secrecy Leaks |
| MIRAI | rust, static | Panic, Security bugs, Correctness |
| ERASan | rust, dynamic | Memory access bugs |
| shuttle | rust, dynamic | Concurrency bugs |
| kani | rust, verifier | Memory safety, User-specified assertions, Panics, Unexpected behavior (e.g., arithmetic overflows) |
| GCatch | go, static | Concurrency bugs |
| GFuzz | go, dynamic | Concurrency bugs |
| cppcheck | C/C++, static | Common C/C++ bugs |
| slither | solidity, static | Common Solidity bugs |
| PeCatch | solidity, static | Gas-fee bugs | 

## 🐛 Bugs Found

200+ bugs are found, reported, and fixed by the checkers

See `./detection-results/'Github Bug Report.xlsx'`

## 🛣️ Roadmap

- [x] An integrated environment for the deployment of all the Rust static checkers.
- [x] Parse the various detection results and connect to the frontend.
- [x] Implement the rule engine to improve the accuracy of detection results.
- [x] Add options to dump the result to json files for easier parsing and integration with AI.
- [ ] Design and implement APIs for better integration with web3 ecosystems.
- [ ] Test and integrate more solidity checkers and parsing the results.
- [ ] Integrate different levels of checkers with the payment and staking systems.
- [ ] Build new middle-layer analysis result cache to reduce the computation costs.
- [ ] Launch a large-scale scan for the web3 foundational infrustructure.
- [ ] To become a basic security service provider for web3


## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read our [Contributing Guidelines](CONTRIBUTING.md) for more details.

## 📄 License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

For security-related issues, please refer to our [Security Policy](SECURITY.md).

