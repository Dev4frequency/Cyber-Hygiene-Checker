class PasswordStrengthMeter {
    constructor() {
        this.commonPasswords = new Set([
            'password', '123456', '123456789', 'qwerty', 'abc123', 'monkey', 
            'letmein', 'dragon', '111111', 'baseball', 'iloveyou', 'trustno1',
            'sunshine', 'master', '123123', 'welcome', 'shadow', 'ashley',
            'football', 'jesus', 'michael', 'ninja', 'mustang', 'password1',
            'admin', 'root', 'guest', 'test', 'user', 'login', 'passw0rd',
            'p@ssword', 'password123', '12345678', 'qwertyuiop', 'asdfghjkl',
            'zxcvbnm', '1234567890', 'abcdefghijk', 'adminadmin', 'rootroot'
        ]);
        
        this.commonWords = new Set([
            'love', 'hate', 'good', 'bad', 'happy', 'sad', 'computer', 'internet',
            'phone', 'mobile', 'email', 'facebook', 'google', 'amazon', 'apple',
            'microsoft', 'windows', 'linux', 'android', 'iphone', 'samsung',
            'family', 'friend', 'house', 'home', 'work', 'school', 'college',
            'university', 'company', 'business', 'money', 'bank', 'card',
            'number', 'birthday', 'date', 'year', 'month', 'day', 'time',
            'my', 'your', 'his', 'her', 'their', 'our', 'password', 'admin',
            'user', 'test', 'login', 'account', 'secure', 'private', 'secret'
        ]);
        
        this.keyboardPatterns = [
            'qwerty', 'qwertyuiop', 'asdf', 'asdfghjkl', 'zxcv', 'zxcvbnm',
            'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
            'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl',
            'zxcv', 'xcvb', 'cvbn', 'vbnm', '1234', '2345', '3456', '4567',
            '5678', '6789', '7890', '12345', '23456', '34567', '45678',
            '56789', '67890', '123456', '234567', '345678', '456789',
            '567890', '1234567', '2345678', '3456789', '4567890'
        ];
        
        this.setupEventListeners();
    }
    
    setupEventListeners() {
        const passwordInput = document.getElementById('password');
        const toggleBtn = document.getElementById('toggleVisibility');
        
        passwordInput.addEventListener('input', (e) => {
            this.analyzePassword(e.target.value);
        });
        
        toggleBtn.addEventListener('click', () => {
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
            toggleBtn.textContent = type === 'password' ? '👁️' : '🙈';
        });
    }
    
    analyzePassword(password) {
        if (!password) {
            this.resetDisplay();
            return;
        }
        
        const analysis = this.getPasswordAnalysis(password);
        this.updateDisplay(analysis);
    }
    
    getPasswordAnalysis(password) {
        const entropy = this.calculateEntropy(password);
        const characterSets = this.getCharacterSets(password);
        const patterns = this.detectPatterns(password);
        const dictionaryChecks = this.checkDictionary(password);
        const strength = this.calculateOverallStrength(password, entropy, patterns, dictionaryChecks);
        const crackTime = this.estimateCrackTime(entropy);
        
        return {
            password,
            length: password.length,
            entropy,
            characterSets,
            patterns,
            dictionaryChecks,
            strength,
            crackTime,
            feedback: this.generateFeedback(password, entropy, patterns, dictionaryChecks, characterSets)
        };
    }
    
    calculateEntropy(password) {
        if (!password) return 0;
        
        // Calculate character space
        let charSpace = 0;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);
        
        if (hasLower) charSpace += 26;
        if (hasUpper) charSpace += 26;
        if (hasNumber) charSpace += 10;
        if (hasSymbol) charSpace += 32; // Common symbols
        
        // Basic entropy calculation: log2(charSpace^length)
        const basicEntropy = password.length * Math.log2(charSpace);
        
        // Adjust for patterns and repetition (more realistic penalties)
        const repetitionPenalty = this.calculateRepetitionPenalty(password);
        const patternPenalty = this.calculatePatternPenalty(password);
        
        // More aggressive penalties for real-world scenarios
        const adjustedEntropy = basicEntropy * (1 - repetitionPenalty * 1.2) * (1 - patternPenalty * 1.3);
        
        return Math.max(0, Math.round(adjustedEntropy * 10) / 10);
    }
    
    calculateRepetitionPenalty(password) {
        const chars = password.split('');
        const charCounts = {};
        
        chars.forEach(char => {
            charCounts[char] = (charCounts[char] || 0) + 1;
        });
        
        const maxRepeat = Math.max(...Object.values(charCounts));
        const repetitionRatio = maxRepeat / password.length;
        
        // Higher penalty for more repetition
        return Math.min(0.8, repetitionRatio * 1.5);
    }
    
    calculatePatternPenalty(password) {
        const lowerPassword = password.toLowerCase();
        let penaltySum = 0;
        
        // Check for keyboard patterns
        for (const pattern of this.keyboardPatterns) {
            if (lowerPassword.includes(pattern)) {
                penaltySum += pattern.length / password.length * 0.6;
            }
        }
        
        // Check for sequences
        const sequences = this.findSequences(password);
        if (sequences.length > 0) {
            const longestSequence = Math.max(...sequences.map(s => s.length));
            penaltySum += longestSequence / password.length * 0.5;
        }
        
        // Check for common word patterns
        if (lowerPassword.includes('password')) penaltySum += 0.4;
        if (lowerPassword.includes('admin')) penaltySum += 0.4;
        if (lowerPassword.includes('user')) penaltySum += 0.3;
        if (lowerPassword.includes('test')) penaltySum += 0.3;
        if (lowerPassword.includes('login')) penaltySum += 0.3;
        
        // Check for predictable number patterns
        if (/\d{4,}/.test(password)) penaltySum += 0.3;
        if (/20\d{2}/.test(password)) penaltySum += 0.2; // Years like 2024
        if (/19\d{2}/.test(password)) penaltySum += 0.2; // Years like 1990
        
        return Math.min(0.8, penaltySum);
    }
    
    getCharacterSets(password) {
        const sets = [];
        if (/[a-z]/.test(password)) sets.push('lowercase');
        if (/[A-Z]/.test(password)) sets.push('uppercase');
        if (/[0-9]/.test(password)) sets.push('numbers');
        if (/[^a-zA-Z0-9]/.test(password)) sets.push('symbols');
        return sets;
    }
    
    detectPatterns(password) {
        const patterns = [];
        const lowerPassword = password.toLowerCase();
        
        // Keyboard patterns
        for (const pattern of this.keyboardPatterns) {
            if (lowerPassword.includes(pattern)) {
                patterns.push({
                    type: 'keyboard',
                    pattern: pattern,
                    description: `Keyboard pattern "${pattern}" detected`
                });
            }
        }
        
        // Sequences (ascending/descending)
        const sequences = this.findSequences(password);
        sequences.forEach(seq => {
            patterns.push({
                type: 'sequence',
                pattern: seq,
                description: `Sequential pattern "${seq}" detected`
            });
        });
        
        // Repetition patterns
        const repetitions = this.findRepetitions(password);
        repetitions.forEach(rep => {
            patterns.push({
                type: 'repetition',
                pattern: rep,
                description: `Repeated pattern "${rep}" detected`
            });
        });
        
        // Date patterns
        const datePatterns = this.findDatePatterns(password);
        datePatterns.forEach(date => {
            patterns.push({
                type: 'date',
                pattern: date,
                description: `Possible date pattern "${date}" detected`
            });
        });
        
        // Common word patterns (CRITICAL FIX!)
        if (lowerPassword.includes('password')) {
            patterns.push({
                type: 'common_word',
                pattern: 'password',
                description: 'Common word "password" detected'
            });
        }
        if (lowerPassword.includes('admin')) {
            patterns.push({
                type: 'common_word',
                pattern: 'admin',
                description: 'Common word "admin" detected'
            });
        }
        if (lowerPassword.includes('user')) {
            patterns.push({
                type: 'common_word',
                pattern: 'user',
                description: 'Common word "user" detected'
            });
        }
        if (lowerPassword.includes('test')) {
            patterns.push({
                type: 'common_word',
                pattern: 'test',
                description: 'Common word "test" detected'
            });
        }
        if (lowerPassword.includes('login')) {
            patterns.push({
                type: 'common_word',
                pattern: 'login',
                description: 'Common word "login" detected'
            });
        }
        
        // Number pattern detection
        if (/\d{4,}/.test(password)) {
            patterns.push({
                type: 'number_sequence',
                pattern: '4+ digits',
                description: 'Long number sequence detected'
            });
        }
        if (/20\d{2}/.test(password)) {
            patterns.push({
                type: 'year_pattern',
                pattern: '20XX year',
                description: 'Predictable year pattern detected'
            });
        }
        
        return patterns;
    }
    
    findSequences(password) {
        const sequences = [];
        const lowerPassword = password.toLowerCase();
        
        for (let i = 0; i < lowerPassword.length - 2; i++) {
            let sequence = lowerPassword[i];
            let currentChar = lowerPassword[i].charCodeAt(0);
            
            // Check ascending
            for (let j = i + 1; j < lowerPassword.length; j++) {
                const nextChar = lowerPassword[j].charCodeAt(0);
                if (nextChar === currentChar + 1) {
                    sequence += lowerPassword[j];
                    currentChar = nextChar;
                } else {
                    break;
                }
            }
            
            if (sequence.length >= 3) {
                sequences.push(sequence);
            }
            
            // Check descending
            sequence = lowerPassword[i];
            currentChar = lowerPassword[i].charCodeAt(0);
            
            for (let j = i + 1; j < lowerPassword.length; j++) {
                const nextChar = lowerPassword[j].charCodeAt(0);
                if (nextChar === currentChar - 1) {
                    sequence += lowerPassword[j];
                    currentChar = nextChar;
                } else {
                    break;
                }
            }
            
            if (sequence.length >= 3) {
                sequences.push(sequence);
            }
        }
        
        return sequences;
    }
    
    findRepetitions(password) {
        const repetitions = [];
        const regex = /(.{2,})\1+/g;
        let match;
        
        while ((match = regex.exec(password)) !== null) {
            repetitions.push(match[0]);
        }
        
        return repetitions;
    }
    
    findDatePatterns(password) {
        const datePatterns = [];
        
        // Common date formats
        const dateRegexes = [
            /\d{1,2}\/\d{1,2}\/\d{2,4}/g,  // MM/DD/YYYY
            /\d{1,2}-\d{1,2}-\d{2,4}/g,    // MM-DD-YYYY
            /\d{1,2}\.\d{1,2}\.\d{2,4}/g,  // MM.DD.YYYY
            /\d{4}\d{2}\d{2}/g,            // YYYYMMDD
            /\d{2}\d{2}\d{4}/g,            // MMDDYYYY
            /(19|20)\d{2}/g                // Years 1900-2099
        ];
        
        dateRegexes.forEach(regex => {
            let match;
            while ((match = regex.exec(password)) !== null) {
                datePatterns.push(match[0]);
            }
        });
        
        return datePatterns;
    }
    
    checkDictionary(password) {
        const checks = {
            commonPassword: this.commonPasswords.has(password.toLowerCase()),
            containsCommonWord: false,
            commonWords: []
        };
        
        const lowerPassword = password.toLowerCase();
        
        // Check for common words (substring match)
        for (const word of this.commonWords) {
            if (lowerPassword.includes(word)) {
                checks.containsCommonWord = true;
                checks.commonWords.push(word);
            }
        }
        
        return checks;
    }
    
    calculateOverallStrength(password, entropy, patterns, dictionaryChecks) {
        let score = 0;
        
        // Debug logging
        console.log('=== PASSWORD ANALYSIS DEBUG ===');
        console.log('Password:', password);
        console.log('Entropy:', entropy);
        console.log('Patterns found:', patterns);
        console.log('Dictionary checks:', dictionaryChecks);
        
        // Base score from entropy (more realistic thresholds)
        if (entropy >= 80) score += 45;
        else if (entropy >= 60) score += 35;
        else if (entropy >= 40) score += 25;
        else if (entropy >= 25) score += 15;
        else if (entropy >= 15) score += 8;
        
        // Length bonus (stricter requirements)
        if (password.length >= 16) score += 25;
        else if (password.length >= 12) score += 20;
        else if (password.length >= 10) score += 15;
        else if (password.length >= 8) score += 10;
        else if (password.length >= 6) score += 5;
        
        // Character variety bonus (more important)
        const charSets = this.getCharacterSets(password);
        score += charSets.length * 8;
        
        console.log('Base score after entropy, length, and variety:', score);
        
        // Penalties (stricter)
        if (dictionaryChecks.commonPassword) {
            score -= 50;
            console.log('Common password penalty: -50');
        }
        if (dictionaryChecks.containsCommonWord) {
            score -= 20;
            console.log('Common word penalty: -20');
        }
        if (patterns.length > 0) {
            const patternPenalty = patterns.length * 15;
            score -= patternPenalty;
            console.log('Pattern penalty:', -patternPenalty);
        }
        
        // Additional penalties for common patterns
        if (password.toLowerCase().includes('password')) {
            score -= 30;
            console.log('Contains "password" penalty: -30');
        }
        if (password.toLowerCase().includes('admin')) {
            score -= 25;
            console.log('Contains "admin" penalty: -25');
        }
        if (password.toLowerCase().includes('user')) {
            score -= 20;
            console.log('Contains "user" penalty: -20');
        }
        
        // Penalty for predictable number sequences
        if (/\d{4,}/.test(password)) {
            score -= 15;
            console.log('4+ digits penalty: -15');
        }
        if (/20\d{2}/.test(password)) {
            score -= 10;
            console.log('Year 20XX penalty: -10');
        }
        
        console.log('Final score before normalization:', score);
        
        // Normalize to 0-100
        score = Math.max(0, Math.min(100, score));
        
        // Determine strength level (stricter thresholds)
        let result;
        if (score >= 85) result = { level: 'very-strong', score, text: 'Very Strong' };
        else if (score >= 70) result = { level: 'strong', score, text: 'Strong' };
        else if (score >= 55) result = { level: 'good', score, text: 'Good' };
        else if (score >= 40) result = { level: 'fair', score, text: 'Fair' };
        else if (score >= 25) result = { level: 'weak', score, text: 'Weak' };
        else result = { level: 'very-weak', score, text: 'Very Weak' };
        
        console.log('Final result:', result);
        console.log('=== END DEBUG ===');
        
        return result;
    }
    
    estimateCrackTime(entropy) {
        if (entropy <= 0) return 'Instant';
        
        // Assuming 1 billion guesses per second
        const guessesPerSecond = 1e9;
        const totalGuesses = Math.pow(2, entropy) / 2; // Average case
        const seconds = totalGuesses / guessesPerSecond;
        
        if (seconds < 1) return 'Instant';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000000) return `${Math.round(seconds / 31536000)} years`;
        return `${Math.round(seconds / 31536000000)} centuries`;
    }
    
    generateFeedback(password, entropy, patterns, dictionaryChecks, characterSets) {
        const feedback = [];
        
        // Length feedback
        if (password.length < 8) {
            feedback.push({
                type: 'negative',
                icon: '❌',
                message: 'Password is too short. Use at least 8 characters.'
            });
        } else if (password.length < 12) {
            feedback.push({
                type: 'warning',
                icon: '⚠️',
                message: 'Consider using 12+ characters for better security.'
            });
        } else {
            feedback.push({
                type: 'positive',
                icon: '✅',
                message: 'Good password length.'
            });
        }
        
        // Character variety feedback
        if (characterSets.length < 3) {
            feedback.push({
                type: 'negative',
                icon: '❌',
                message: 'Use a mix of uppercase, lowercase, numbers, and symbols.'
            });
        } else if (characterSets.length === 3) {
            feedback.push({
                type: 'warning',
                icon: '⚠️',
                message: 'Good variety. Consider adding more character types.'
            });
        } else {
            feedback.push({
                type: 'positive',
                icon: '✅',
                message: 'Excellent character variety.'
            });
        }
        
        // Dictionary checks
        if (dictionaryChecks.commonPassword) {
            feedback.push({
                type: 'negative',
                icon: '❌',
                message: 'This is a very common password. Choose something unique.'
            });
        }
        
        if (dictionaryChecks.containsCommonWord) {
            feedback.push({
                type: 'warning',
                icon: '⚠️',
                message: `Contains common words: ${dictionaryChecks.commonWords.join(', ')}`
            });
        }
        
        // Pattern feedback
        if (patterns.length > 0) {
            const patternTypes = [...new Set(patterns.map(p => p.type))];
            feedback.push({
                type: 'negative',
                icon: '❌',
                message: `Avoid ${patternTypes.join(', ')} patterns.`
            });
        } else if (password.length >= 8) {
            feedback.push({
                type: 'positive',
                icon: '✅',
                message: 'No common patterns detected.'
            });
        }
        
        // Entropy feedback
        if (entropy >= 50) {
            feedback.push({
                type: 'positive',
                icon: '✅',
                message: 'High randomness - excellent entropy.'
            });
        } else if (entropy >= 25) {
            feedback.push({
                type: 'warning',
                icon: '⚠️',
                message: 'Moderate randomness - consider more variation.'
            });
        } else if (password.length > 0) {
            feedback.push({
                type: 'negative',
                icon: '❌',
                message: 'Low randomness - very predictable.'
            });
        }
        
        return feedback;
    }
    
    updateDisplay(analysis) {
        // Update metrics with animation
        this.animateMetricUpdate('entropy', `${analysis.entropy} bits`);
        this.animateMetricUpdate('length', `${analysis.length} chars`);
        this.animateMetricUpdate('charSets', analysis.characterSets.length);
        this.animateMetricUpdate('crackTime', analysis.crackTime);
        
        // Update strength meter
        const progressBar = document.getElementById('strengthProgress');
        const strengthText = document.getElementById('strengthText');
        const strengthScore = document.getElementById('strengthScore');
        const strengthMeter = document.querySelector('.strength-meter');
        
        // Update ARIA attributes
        strengthMeter.setAttribute('aria-valuenow', analysis.strength.score);
        strengthMeter.setAttribute('aria-valuetext', `${analysis.strength.text} - ${analysis.strength.score} out of 100`);
        
        progressBar.className = `strength-progress ${analysis.strength.level}`;
        strengthText.textContent = analysis.strength.text;
        strengthScore.textContent = `${analysis.strength.score}/100`;
        
        // Update feedback with smooth transitions
        this.updateFeedback(analysis.feedback);
        
        // Update patterns with smooth transitions
        this.updatePatterns(analysis.patterns);
    }
    
    animateMetricUpdate(elementId, newValue) {
        const element = document.getElementById(elementId);
        const currentValue = element.textContent;
        
        if (currentValue !== newValue) {
            element.style.transform = 'scale(1.1)';
            element.style.opacity = '0.7';
            
            setTimeout(() => {
                element.textContent = newValue;
                element.style.transform = 'scale(1)';
                element.style.opacity = '1';
            }, 150);
        }
    }
    
    updateFeedback(feedback) {
        const feedbackContainer = document.getElementById('feedback');
        const currentItems = feedbackContainer.querySelectorAll('.feedback-item');
        
        // Fade out current items
        currentItems.forEach(item => {
            item.style.opacity = '0';
            item.style.transform = 'translateX(-10px)';
        });
        
        setTimeout(() => {
            feedbackContainer.innerHTML = '';
            
            feedback.forEach((item, index) => {
                const feedbackDiv = document.createElement('div');
                feedbackDiv.className = `feedback-item ${item.type}`;
                feedbackDiv.setAttribute('role', 'listitem');
                feedbackDiv.innerHTML = `
                    <span class="feedback-icon" aria-hidden="true">${item.icon}</span>
                    <span>${item.message}</span>
                `;
                
                // Initial state for animation
                feedbackDiv.style.opacity = '0';
                feedbackDiv.style.transform = 'translateX(10px)';
                
                feedbackContainer.appendChild(feedbackDiv);
                
                // Animate in
                setTimeout(() => {
                    feedbackDiv.style.opacity = '1';
                    feedbackDiv.style.transform = 'translateX(0)';
                }, index * 50);
            });
        }, 200);
    }
    
    updatePatterns(patterns) {
        const patternsContainer = document.getElementById('patterns');
        const currentItems = patternsContainer.querySelectorAll('.pattern-item');
        
        // Fade out current items
        currentItems.forEach(item => {
            item.style.opacity = '0';
            item.style.transform = 'translateY(-5px)';
        });
        
        setTimeout(() => {
            patternsContainer.innerHTML = '';
            
            if (patterns.length === 0) {
                const patternDiv = document.createElement('div');
                patternDiv.className = 'pattern-item';
                patternDiv.setAttribute('role', 'listitem');
                patternDiv.innerHTML = `
                    <span class="pattern-name">Common Patterns:</span>
                    <span class="pattern-status">None detected</span>
                `;
                patternDiv.style.opacity = '0';
                patternDiv.style.transform = 'translateY(5px)';
                patternsContainer.appendChild(patternDiv);
                
                setTimeout(() => {
                    patternDiv.style.opacity = '1';
                    patternDiv.style.transform = 'translateY(0)';
                }, 100);
            } else {
                patterns.forEach((pattern, index) => {
                    const patternDiv = document.createElement('div');
                    patternDiv.className = 'pattern-item';
                    patternDiv.setAttribute('role', 'listitem');
                    patternDiv.innerHTML = `
                        <span class="pattern-name">${pattern.type}:</span>
                        <span class="pattern-status detected">${pattern.pattern}</span>
                    `;
                    patternDiv.style.opacity = '0';
                    patternDiv.style.transform = 'translateY(5px)';
                    patternsContainer.appendChild(patternDiv);
                    
                    setTimeout(() => {
                        patternDiv.style.opacity = '1';
                        patternDiv.style.transform = 'translateY(0)';
                    }, 100 + (index * 30));
                });
            }
        }, 150);
    }
    
    resetDisplay() {
        document.getElementById('entropy').textContent = '0 bits';
        document.getElementById('length').textContent = '0 chars';
        document.getElementById('charSets').textContent = '0';
        document.getElementById('crackTime').textContent = 'Instant';
        
        const progressBar = document.getElementById('strengthProgress');
        progressBar.className = 'strength-progress';
        progressBar.style.width = '0%';
        
        document.getElementById('strengthText').textContent = 'Enter a password';
        document.getElementById('strengthScore').textContent = '';
        
        document.getElementById('feedback').innerHTML = `
            <div class="feedback-item neutral">
                <span class="feedback-icon">ℹ️</span>
                <span>Enter a password to see detailed analysis</span>
            </div>
        `;
        
        document.getElementById('patterns').innerHTML = `
            <div class="pattern-item">
                <span class="pattern-name">Common Patterns:</span>
                <span class="pattern-status">None detected</span>
            </div>
        `;
    }
}

// Initialize PassMeter when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PasswordStrengthMeter();
});