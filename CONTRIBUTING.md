# Contributing to MR-X

First off, thank you for considering contributing to MR-X! It's people like you that make MR-X such a great tool.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [support@Mxui-panel.com](mailto:support@Mxui-panel.com).

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Go 1.22 or higher
- Git
- Make
- Docker (optional, for container development)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/MR-X.git
   cd MR-X
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/MR-X-Panel/MR-X.git
   ```

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**When reporting a bug, include:**
- MR-X version (`Mxui version`)
- Operating system and version
- Go version (`go version`)
- Steps to reproduce
- Expected behavior
- Actual behavior
- Relevant logs

**Bug Report Template:**
```markdown
**Describe the bug**
A clear description of the bug.

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected behavior**
What you expected to happen.

**Screenshots/Logs**
If applicable, add screenshots or logs.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- MR-X Version: [e.g., 1.0.0]
- Go Version: [e.g., 1.22]
- Browser: [e.g., Chrome 120]

**Additional context**
Any other context about the problem.
```

### Suggesting Features

Feature requests are welcome! Please provide:

- Clear description of the feature
- Use case and benefits
- Possible implementation approach
- Any alternatives you've considered

### Code Contributions

1. **Small fixes**: Documentation, typos, small bug fixes
2. **Medium features**: New API endpoints, UI improvements
3. **Large features**: New protocols, major architectural changes (discuss first!)

## Development Setup

### 1. Install Dependencies

```bash
# Install Go dependencies
make deps

# Install development tools
make tools
```

### 2. Configuration

```bash
# Copy example config
cp config.yaml config.local.yaml

# Edit configuration
nano config.local.yaml
```

### 3. Run Development Server

```bash
# With hot reload (recommended)
make dev

# Or manual run
make build
./bin/Mxui serve --config config.local.yaml
```

### 4. Run Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cover

# Run specific tests
go test -v ./Core/... -run TestUserCreate
```

### 5. Linting

```bash
# Run linter
make lint

# Format code
make fmt
```

## Style Guidelines

### Go Code Style

We follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and [Effective Go](https://golang.org/doc/effective_go.html).

**Key points:**
- Use `gofmt` for formatting
- Follow naming conventions (CamelCase for exports, camelCase for internal)
- Write meaningful comments for exported functions
- Keep functions focused and small
- Handle errors explicitly

**Example:**
```go
// CreateUser creates a new user with the given parameters.
// It returns the created user or an error if validation fails.
func CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
    if err := req.Validate(); err != nil {
        return nil, fmt.Errorf("validation failed: %w", err)
    }
    
    user := &User{
        Username:  req.Username,
        Email:     req.Email,
        CreatedAt: time.Now(),
    }
    
    if err := db.Create(user).Error; err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }
    
    return user, nil
}
```

### JavaScript Code Style

- Use vanilla JavaScript (no frameworks for core panel)
- Use `const` and `let`, avoid `var`
- Use meaningful variable names
- Comment complex logic

### CSS Style

- Use CSS variables for theming
- Follow BEM naming convention
- Mobile-first approach
- Minimize specificity

### HTML Style

- Use semantic HTML5 elements
- Include accessibility attributes
- Keep templates clean and readable

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

### Examples

```
feat(users): add bulk import functionality

- Support CSV and JSON import formats
- Add progress indicator
- Handle duplicate detection

Closes #123
```

```
fix(auth): resolve JWT token expiration issue

Token was not properly refreshed when nearing expiration.
Added automatic refresh 5 minutes before expiry.

Fixes #456
```

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests:**
   ```bash
   make test
   ```

3. **Run linter:**
   ```bash
   make lint
   ```

4. **Update documentation** if needed

### PR Guidelines

1. **Title**: Use conventional commit format
2. **Description**: Explain what and why
3. **Link issues**: Reference related issues
4. **Small PRs**: Keep changes focused
5. **Screenshots**: Include for UI changes

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed.

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No breaking changes (or documented)

## Related Issues
Fixes #(issue)
```

### Review Process

1. At least one maintainer review required
2. All CI checks must pass
3. No merge conflicts
4. Squash commits if requested

## Project Structure

```
MR-X/
├── Core/               # Go backend code
│   ├── main.go        # Entry point
│   ├── api.go         # API handlers
│   ├── database.go    # Database operations
│   ├── users.go       # User management
│   └── ...
├── Web/               # Frontend assets
│   ├── index.html     # Main page
│   ├── dashboard.html # Dashboard
│   ├── styles.css     # Styles
│   ├── app.js         # Main JavaScript
│   └── ...
├── docs/              # Documentation
├── scripts/           # Helper scripts
└── ...
```

## Getting Help

- **Documentation**: [Wiki](https://github.com/MR-X-Panel/MR-X/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/MR-X-Panel/MR-X/discussions)
- **Telegram**: [@mxui_support](https://t.me/mxui_support)

## Recognition

Contributors are recognized in:
- [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- Release notes
- Project README

Thank you for contributing! 🎉
