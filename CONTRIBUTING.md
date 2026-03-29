# Contributing to DetectIQ

Thank you for your interest in contributing to DetectIQ! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Respect differing viewpoints and experiences

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check the [existing issues](https://github.com/vamshi-narahari/detect-iq/issues) to avoid duplicates
2. Collect relevant information (browser version, Node.js version, error logs)

When creating a bug report, include:
- Clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Screenshots (if applicable)
- Environment details (OS, Node version, AWS region)

### Suggesting Features

Feature requests are welcome! Please:
- Check existing [discussions](https://github.com/vamshi-narahari/detect-iq/discussions) first
- Explain the use case and why it benefits SOC teams
- Consider implementation complexity

### Code Contributions

#### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/detect-iq.git
   cd detect-iq
   ```

3. Create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. Follow setup instructions in [README.md](README.md)

#### Coding Standards

**Backend (Node.js):**
- Use ES6+ syntax
- Handle errors properly (try/catch for async operations)
- Validate user input
- Use meaningful variable names
- Add comments for complex logic
- Set appropriate `max_tokens` for AI calls (4000+ for complex outputs)

**Frontend (React):**
- Use functional components with hooks
- Keep components focused and reusable
- Use descriptive component and variable names
- Handle loading and error states
- Follow existing file structure in `App.jsx`

**General:**
- Keep changes focused (one feature/fix per PR)
- Don't add unnecessary dependencies
- Ensure code works across all supported SIEM platforms
- Test with AWS Bedrock before submitting

#### Testing Changes

Before submitting:
1. Test the feature manually
2. Verify it works with multiple SIEM platforms (if applicable)
3. Check browser console for errors
4. Test with different input sizes and edge cases
5. Ensure backend responds within reasonable time

#### Git Commit Messages

Use clear, descriptive commit messages:
```
feat: add Sigma rule export to detection builder
fix: resolve 413 error for large log payloads
docs: update AWS Bedrock setup instructions
refactor: extract detection chain logic into separate component
```

Prefixes:
- `feat:` - new feature
- `fix:` - bug fix
- `docs:` - documentation changes
- `refactor:` - code refactoring
- `perf:` - performance improvements
- `test:` - adding tests
- `chore:` - maintenance tasks

#### Pull Request Process

1. Update README.md if adding features
2. Ensure your code follows the coding standards
3. Test thoroughly
4. Create a pull request with:
   - Clear title describing the change
   - Description of what changed and why
   - Reference any related issues (#123)
   - Screenshots/GIFs for UI changes

5. Respond to review feedback promptly

## Areas for Contribution

### Easy (Good First Issues)
- Add new SIEM platforms to query translator
- Improve error messages
- Add screenshots to README
- Fix typos in documentation
- Add more ATT&CK techniques to autopilot

### Medium
- Implement dark mode
- Add detection export formats (Sigma, Elastic rules)
- Improve UI/UX of existing features
- Add unit tests
- Optimize bundle size (code splitting)

### Advanced
- Add detection version control
- Implement multi-user workspace support
- Add custom AI model support (beyond Bedrock)
- Build CLI tool for DetectIQ
- Add integration with SOAR platforms

## Questions?

- Open a [discussion](https://github.com/vamshi-narahari/detect-iq/discussions)
- Check existing issues and PRs
- Review README and documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make DetectIQ better for the security community! 🛡️
