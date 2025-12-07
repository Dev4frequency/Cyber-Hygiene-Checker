# Cyber Hygiene Checker- Modern Password Strength Analyzer

A professional password strength analyzer built with Flask and modern JavaScript. Features advanced entropy calculation, pattern detection, and a clean glassmorphism UI design.

## Features

- **Real-time Analysis**: Instant password strength feedback as you type
- **Entropy Calculation**: Advanced cryptographic strength measurement
- **Pattern Detection**: Identifies common weak patterns like keyboard sequences and repetitions
- **Security Recommendations**: Actionable tips to improve password strength
- **Modern UI**: Clean, responsive design with smooth animations
- **Accessibility**: Built with semantic HTML and ARIA attributes


### Example Passwords

Try these examples to see how the analyzer works:

- **Very Weak**: `password123` - Common word "password" + predictable numbers
- **Weak**: `MyPassword2024!` - Contains "My", "Password", and year "2024"  
- **Fair**: `abc123def` - Mixed case and numbers, but predictable patterns
- **Good**: `Tr0ub4dor&3` - Mixed case, numbers, symbols, no common words
- **Strong**: `jazz-piano-mountain-89!` - Passphrase with good entropy
- **Very Strong**: `K9#mP$vL2@nX7&qR5!` - Random characters with maximum entropy

## Getting Started

### Prerequisites
- Python 3.7+
- pip

### Installation
```bash
git clone https://github.com/twmiles/passmeter.git
cd passmeter
pip install -r requirements.txt
python app.py
```

The application will be available at `http://localhost:5000`

## Project Structure
```
passmeter/
├── app.py                 # Flask backend
├── index.html            # Main frontend
├── styles.css            # Styling and animations
├── password-strength.js  # Frontend logic
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## How It Works

The analyzer evaluates passwords using multiple criteria:

1. **Character Set Analysis**: Checks for mixed case, numbers, and symbols
2. **Entropy Calculation**: Measures true cryptographic strength
3. **Pattern Detection**: Identifies common weak patterns
4. **Dictionary Checks**: Warns about common passwords
5. **Length Assessment**: Considers minimum length requirements

## API Endpoints

- `GET /` - Main application
- `GET /api/health` - Health check
- `POST /api/analyze` - Password analysis
- `GET /api/docs` - API documentation

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## About

PassMeter was created to provide a modern, accessible tool for password security assessment. Built with best practices in mind, it combines security analysis with a beautiful user experience.

---

**Cyber Hygiene Checker** - Making password security beautiful and accessible
<em>Built with RESPECT BY YASH BISHT for better password security</em>