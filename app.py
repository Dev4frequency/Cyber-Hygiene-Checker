from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
import math
import string
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

class PasswordStrengthAPI:
    def __init__(self):
        # Common passwords dataset (subset for demo)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 'monkey',
            'letmein', 'dragon', '111111', 'baseball', 'iloveyou', 'trustno1',
            'sunshine', 'master', '123123', 'welcome', 'shadow', 'ashley',
            'football', 'jesus', 'michael', 'ninja', 'mustang', 'password1',
            'admin', 'root', 'guest', 'test', 'user', 'login', 'passw0rd',
            'p@ssword', 'password123', '12345678', 'qwertyuiop', 'asdfghjkl',
            'zxcvbnm', '1234567890', 'abcdefghijk', 'adminadmin', 'rootroot'
        }
        
        # Common words that might appear in passwords
        self.common_words = {
            'love', 'hate', 'good', 'bad', 'happy', 'sad', 'computer', 'internet',
            'phone', 'mobile', 'email', 'facebook', 'google', 'amazon', 'apple',
            'microsoft', 'windows', 'linux', 'android', 'iphone', 'samsung',
            'family', 'friend', 'house', 'home', 'work', 'school', 'college',
            'university', 'company', 'business', 'money', 'bank', 'card',
            'number', 'birthday', 'date', 'year', 'month', 'day', 'time'
        }
        
        # Keyboard patterns
        self.keyboard_patterns = [
            'qwerty', 'qwertyuiop', 'asdf', 'asdfghjkl', 'zxcv', 'zxcvbnm',
            'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
            'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl',
            'zxcv', 'xcvb', 'cvbn', 'vbnm', '1234', '2345', '3456', '4567',
            '5678', '6789', '7890', '12345', '23456', '34567', '45678',
            '56789', '67890', '123456', '234567', '345678', '456789',
            '567890', '1234567', '2345678', '3456789', '4567890'
        ]
    
    def calculate_entropy(self, password):
        """Calculate password entropy considering character space and patterns"""
        if not password:
            return 0
        
        # Determine character space
        char_space = 0
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        if has_lower:
            char_space += 26
        if has_upper:
            char_space += 26
        if has_digit:
            char_space += 10
        if has_symbol:
            char_space += 32  # Common symbols
        
        if char_space == 0:
            return 0
        
        # Basic entropy calculation
        basic_entropy = len(password) * math.log2(char_space)
        
        # Apply penalties for patterns and repetition
        repetition_penalty = self._calculate_repetition_penalty(password)
        pattern_penalty = self._calculate_pattern_penalty(password)
        
        adjusted_entropy = basic_entropy * (1 - repetition_penalty) * (1 - pattern_penalty)
        
        return max(0, round(adjusted_entropy, 1))
    
    def _calculate_repetition_penalty(self, password):
        """Calculate penalty for character repetition"""
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        max_repeat = max(char_counts.values()) if char_counts else 1
        repetition_ratio = max_repeat / len(password)
        
        return min(0.8, repetition_ratio * 1.5)
    
    def _calculate_pattern_penalty(self, password):
        """Calculate penalty for common patterns"""
        lower_password = password.lower()
        penalty_sum = 0
        
        # Check keyboard patterns
        for pattern in self.keyboard_patterns:
            if pattern in lower_password:
                penalty_sum += len(pattern) / len(password) * 0.5
        
        # Check for sequences
        sequences = self._find_sequences(password)
        if sequences:
            longest_sequence = max(len(seq) for seq in sequences)
            penalty_sum += longest_sequence / len(password) * 0.4
        
        return min(0.8, penalty_sum)
    
    def _find_sequences(self, password):
        """Find ascending/descending character sequences"""
        sequences = []
        lower_password = password.lower()
        
        for i in range(len(lower_password) - 2):
            # Check ascending sequence
            sequence = lower_password[i]
            current_ord = ord(lower_password[i])
            
            for j in range(i + 1, len(lower_password)):
                next_ord = ord(lower_password[j])
                if next_ord == current_ord + 1:
                    sequence += lower_password[j]
                    current_ord = next_ord
                else:
                    break
            
            if len(sequence) >= 3:
                sequences.append(sequence)
            
            # Check descending sequence
            sequence = lower_password[i]
            current_ord = ord(lower_password[i])
            
            for j in range(i + 1, len(lower_password)):
                next_ord = ord(lower_password[j])
                if next_ord == current_ord - 1:
                    sequence += lower_password[j]
                    current_ord = next_ord
                else:
                    break
            
            if len(sequence) >= 3:
                sequences.append(sequence)
        
        return sequences
    
    def detect_patterns(self, password):
        """Detect various patterns in the password"""
        patterns = []
        lower_password = password.lower()
        
        # Keyboard patterns
        for pattern in self.keyboard_patterns:
            if pattern in lower_password:
                patterns.append({
                    'type': 'keyboard',
                    'pattern': pattern,
                    'description': f'Keyboard pattern "{pattern}" detected'
                })
        
        # Sequences
        sequences = self._find_sequences(password)
        for seq in sequences:
            patterns.append({
                'type': 'sequence',
                'pattern': seq,
                'description': f'Sequential pattern "{seq}" detected'
            })
        
        # Repetitions
        repetitions = self._find_repetitions(password)
        for rep in repetitions:
            patterns.append({
                'type': 'repetition',
                'pattern': rep,
                'description': f'Repeated pattern "{rep}" detected'
            })
        
        # Date patterns
        date_patterns = self._find_date_patterns(password)
        for date in date_patterns:
            patterns.append({
                'type': 'date',
                'pattern': date,
                'description': f'Possible date pattern "{date}" detected'
            })
        
        return patterns
    
    def _find_repetitions(self, password):
        """Find repeated substrings"""
        repetitions = []
        pattern = re.compile(r'(.{2,})\1+')
        
        for match in pattern.finditer(password):
            repetitions.append(match.group(0))
        
        return repetitions
    
    def _find_date_patterns(self, password):
        """Find potential date patterns"""
        date_patterns = []
        
        # Common date formats
        date_regexes = [
            r'\d{1,2}\/\d{1,2}\/\d{2,4}',  # MM/DD/YYYY
            r'\d{1,2}-\d{1,2}-\d{2,4}',    # MM-DD-YYYY
            r'\d{1,2}\.\d{1,2}\.\d{2,4}',  # MM.DD.YYYY
            r'\d{8}',                       # YYYYMMDD
            r'(19|20)\d{2}'                 # Years 1900-2099
        ]
        
        for regex in date_regexes:
            matches = re.findall(regex, password)
            date_patterns.extend(matches)
        
        return date_patterns
    
    def check_dictionary(self, password):
        """Check password against common dictionaries"""
        lower_password = password.lower()
        
        checks = {
            'is_common_password': lower_password in self.common_passwords,
            'contains_common_words': False,
            'common_words_found': []
        }
        
        # Check for common words
        for word in self.common_words:
            if word in lower_password:
                checks['contains_common_words'] = True
                checks['common_words_found'].append(word)
        
        return checks
    
    def get_character_sets(self, password):
        """Determine which character sets are used"""
        sets = []
        if re.search(r'[a-z]', password):
            sets.append('lowercase')
        if re.search(r'[A-Z]', password):
            sets.append('uppercase')
        if re.search(r'[0-9]', password):
            sets.append('numbers')
        if re.search(r'[^a-zA-Z0-9]', password):
            sets.append('symbols')
        return sets
    
    def calculate_strength_score(self, password, entropy, patterns, dictionary_checks):
        """Calculate overall password strength score (0-100)"""
        score = 0
        
        # Base score from entropy
        if entropy >= 60:
            score += 40
        elif entropy >= 40:
            score += 30
        elif entropy >= 25:
            score += 20
        elif entropy >= 15:
            score += 10
        
        # Length bonus
        length = len(password)
        if length >= 12:
            score += 20
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        elif length >= 4:
            score += 5
        
        # Character variety bonus
        char_sets = self.get_character_sets(password)
        score += len(char_sets) * 5
        
        # Penalties
        if dictionary_checks['is_common_password']:
            score -= 40
        if dictionary_checks['contains_common_words']:
            score -= 15
        if patterns:
            score -= len(patterns) * 10
        
        # Normalize to 0-100
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 80:
            return {'level': 'strong', 'score': score, 'text': 'Strong'}
        elif score >= 60:
            return {'level': 'good', 'score': score, 'text': 'Good'}
        elif score >= 40:
            return {'level': 'fair', 'score': score, 'text': 'Fair'}
        elif score >= 20:
            return {'level': 'weak', 'score': score, 'text': 'Weak'}
        else:
            return {'level': 'very-weak', 'score': score, 'text': 'Very Weak'}
    
    def estimate_crack_time(self, entropy):
        """Estimate time to crack password"""
        if entropy <= 0:
            return 'Instant'
        
        # Assuming 1 billion guesses per second
        guesses_per_second = 1e9
        total_guesses = (2 ** entropy) / 2  # Average case
        seconds = total_guesses / guesses_per_second
        
        if seconds < 1:
            return 'Instant'
        elif seconds < 60:
            return f'{round(seconds)} seconds'
        elif seconds < 3600:
            return f'{round(seconds / 60)} minutes'
        elif seconds < 86400:
            return f'{round(seconds / 3600)} hours'
        elif seconds < 31536000:
            return f'{round(seconds / 86400)} days'
        elif seconds < 31536000000:
            return f'{round(seconds / 31536000)} years'
        else:
            return f'{round(seconds / 31536000000)} centuries'
    
    def generate_feedback(self, password, entropy, patterns, dictionary_checks, character_sets):
        """Generate detailed feedback for password improvement"""
        feedback = []
        
        # Length feedback
        length = len(password)
        if length < 8:
            feedback.append({
                'type': 'error',
                'message': 'Password is too short. Use at least 8 characters.',
                'severity': 'high'
            })
        elif length < 12:
            feedback.append({
                'type': 'warning',
                'message': 'Consider using 12+ characters for better security.',
                'severity': 'medium'
            })
        else:
            feedback.append({
                'type': 'success',
                'message': 'Good password length.',
                'severity': 'low'
            })
        
        # Character variety feedback
        if len(character_sets) < 3:
            feedback.append({
                'type': 'error',
                'message': 'Use a mix of uppercase, lowercase, numbers, and symbols.',
                'severity': 'high'
            })
        elif len(character_sets) == 3:
            feedback.append({
                'type': 'warning',
                'message': 'Good variety. Consider adding more character types.',
                'severity': 'medium'
            })
        else:
            feedback.append({
                'type': 'success',
                'message': 'Excellent character variety.',
                'severity': 'low'
            })
        
        # Dictionary checks feedback
        if dictionary_checks['is_common_password']:
            feedback.append({
                'type': 'error',
                'message': 'This is a very common password. Choose something unique.',
                'severity': 'critical'
            })
        
        if dictionary_checks['contains_common_words']:
            words = ', '.join(dictionary_checks['common_words_found'])
            feedback.append({
                'type': 'warning',
                'message': f'Contains common words: {words}',
                'severity': 'medium'
            })
        
        # Pattern feedback
        if patterns:
            pattern_types = list(set(p['type'] for p in patterns))
            feedback.append({
                'type': 'error',
                'message': f'Avoid {", ".join(pattern_types)} patterns.',
                'severity': 'high'
            })
        elif length >= 8:
            feedback.append({
                'type': 'success',
                'message': 'No common patterns detected.',
                'severity': 'low'
            })
        
        # Entropy feedback
        if entropy >= 50:
            feedback.append({
                'type': 'success',
                'message': 'High randomness - excellent entropy.',
                'severity': 'low'
            })
        elif entropy >= 25:
            feedback.append({
                'type': 'warning',
                'message': 'Moderate randomness - consider more variation.',
                'severity': 'medium'
            })
        elif length > 0:
            feedback.append({
                'type': 'error',
                'message': 'Low randomness - very predictable.',
                'severity': 'high'
            })
        
        return feedback
    
    def analyze_password(self, password):
        """Comprehensive password analysis"""
        if not password:
            return {
                'error': 'No password provided',
                'status': 'error'
            }
        
        # Perform all analyses
        entropy = self.calculate_entropy(password)
        patterns = self.detect_patterns(password)
        dictionary_checks = self.check_dictionary(password)
        character_sets = self.get_character_sets(password)
        strength = self.calculate_strength_score(password, entropy, patterns, dictionary_checks)
        crack_time = self.estimate_crack_time(entropy)
        feedback = self.generate_feedback(password, entropy, patterns, dictionary_checks, character_sets)
        
        return {
            'status': 'success',
            'analysis': {
                'entropy': entropy,
                'length': len(password),
                'character_sets': character_sets,
                'patterns': patterns,
                'dictionary_checks': dictionary_checks,
                'strength': strength,
                'crack_time': crack_time,
                'feedback': feedback,
                'recommendations': self._generate_recommendations(feedback)
            }
        }
    
    def _generate_recommendations(self, feedback):
        """Generate specific recommendations based on feedback"""
        recommendations = []
        
        error_count = sum(1 for f in feedback if f['type'] == 'error')
        warning_count = sum(1 for f in feedback if f['type'] == 'warning')
        
        if error_count > 0:
            recommendations.append('Address critical security issues first')
        if warning_count > 0:
            recommendations.append('Consider improving areas marked as warnings')
        
        recommendations.extend([
            'Use a unique password for each account',
            'Consider using a password manager',
            'Enable two-factor authentication when available'
        ])
        
        return recommendations

# Initialize the password strength analyzer
password_analyzer = PasswordStrengthAPI()

@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    """API endpoint to analyze password strength"""
    try:
        data = request.get_json()
        
        if not data or 'password' not in data:
            return jsonify({
                'error': 'Password is required',
                'status': 'error'
            }), 400
        
        password = data['password']
        
        # Perform analysis
        result = password_analyzer.analyze_password(password)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f'Internal server error: {str(e)}',
            'status': 'error'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Password Strength API',
        'version': '1.0.0'
    })

@app.route('/', methods=['GET'])
def home():
    """Serve the main HTML frontend"""
    return send_from_directory('.', 'index.html')

@app.route('/styles.css', methods=['GET'])
def styles():
    """Serve the CSS file"""
    return send_from_directory('.', 'styles.css')

@app.route('/password-strength.js', methods=['GET'])
def javascript():
    """Serve the JavaScript file"""
    return send_from_directory('.', 'password-strength.js')

@app.route('/api/docs', methods=['GET'])
def api_docs():
    """API documentation endpoint"""
    return jsonify({
        'service': 'Password Strength API',
        'version': '1.0.0',
        'endpoints': {
            'GET /': 'Password Strength Meter Frontend',
            'POST /api/analyze': 'Analyze password strength',
            'GET /api/health': 'Health check',
            'GET /api/docs': 'API documentation'
        },
        'example_request': {
            'url': '/api/analyze',
            'method': 'POST',
            'body': {
                'password': 'your_password_here'
            }
        }
    })

if __name__ == '__main__':
    # Development mode
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))