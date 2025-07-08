from flask import Flask, render_template, request, jsonify
import re
import math
import hashlib
from typing import Dict, List, Tuple
import os

app = Flask(__name__)

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = set()
        self.load_common_passwords()
    
    def load_common_passwords(self):
        """Load common passwords from file into a set for O(1) lookup"""
        try:
            with open('data/common_passwords.txt', 'r', encoding='utf-8') as f:
                self.common_passwords = {line.strip().lower() for line in f if line.strip()}
            print(f"Loaded {len(self.common_passwords)} common passwords")
        except FileNotFoundError:
            print("Warning: common_passwords.txt not found. Creating sample file.")
            self.create_sample_passwords()
    
    def create_sample_passwords(self):
        """Create a sample common passwords file if it doesn't exist"""
        os.makedirs('data', exist_ok=True)
        sample_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123",
            "Password1", "123456789", "welcome123", "admin123", "qwerty123",
            "password1", "123123", "111111", "1234567", "dragon"
        ]
        
        with open('data/common_passwords.txt', 'w', encoding='utf-8') as f:
            for pwd in sample_passwords:
                f.write(pwd + '\n')
        
        self.common_passwords = {pwd.lower() for pwd in sample_passwords}
    
    def analyze_password(self, password: str) -> Dict:
        """Main password analysis function following the 3-step process"""
        if not password:
            return {"error": "Password cannot be empty"}
        
        analysis = {
            "password": password,
            "step1_common_check": self.step1_check_common_password(password),
            "step2_complexity_analysis": self.step2_analyze_complexity(password),
            "step3_repeating_sequences": self.step3_check_repeating_sequences(password),
            "final_assessment": {}
        }
        
        # Generate final assessment based on all steps
        analysis["final_assessment"] = self.generate_final_assessment(analysis)
        
        return analysis
    
    def step1_check_common_password(self, password: str) -> Dict:
        """Step 1: Check against common passwords"""
        is_common = password.lower() in self.common_passwords
        
        return {
            "is_common": is_common,
            "result": "Instant - You are using a well known password!" if is_common else "Not found in common passwords"
        }
    
    def step2_analyze_complexity(self, password: str) -> Dict:
        """Step 2: Analyze password complexity and calculate breach time"""
        # Check character groups
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[@#$%&\-+*\(\)\[\]{}!?.,;:\'\"~`^=<>/\\|_]', password))
        
        character_groups = {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digits,
            "special": has_special
        }
        
        groups_used = sum(character_groups.values())
        
        # Calculate character space
        char_space = 0
        if has_lower: char_space += 26
        if has_upper: char_space += 26
        if has_digits: char_space += 10
        if has_special: char_space += 32  # Common special characters
        
        # Calculate possible combinations
        total_combinations = char_space ** len(password) if char_space > 0 else 0
        
        # Calculate breach time (100,000 guesses per second)
        guesses_per_second = 100_000
        average_guesses = total_combinations / 2  # Average case
        seconds_to_crack = average_guesses / guesses_per_second
        
        # Generate recommendations if not all groups are used
        recommendations = []
        if not has_lower:
            recommendations.append("Add lowercase letters (a-z)")
        if not has_upper:
            recommendations.append("Add uppercase letters (A-Z)")
        if not has_digits:
            recommendations.append("Add numbers (0-9)")
        if not has_special:
            recommendations.append("Add special characters (@#$%&-+*()[]{})")
        
        return {
            "character_groups": character_groups,
            "groups_used": groups_used,
            "character_space": char_space,
            "total_combinations": total_combinations,
            "combinations_formatted": self.format_combinations_with_comparisons(total_combinations),
            "breach_time_seconds": seconds_to_crack,
            "breach_time_human": self.seconds_to_human_readable(seconds_to_crack),
            "recommendations": recommendations,
            "has_all_groups": groups_used == 4
        }
    
    def step3_check_repeating_sequences(self, password: str) -> Dict:
        """Step 3: Check for repeating sequences and adjust breach time"""
        # Find repeating sequences (2 or more of the same character)
        compressed_password = ""
        repeating_sequences = []
        i = 0
        
        while i < len(password):
            current_char = password[i]
            sequence_length = 1
            
            # Count consecutive identical characters
            while i + sequence_length < len(password) and password[i + sequence_length] == current_char:
                sequence_length += 1
            
            if sequence_length >= 2:
                repeating_sequences.append({
                    "character": current_char,
                    "length": sequence_length,
                    "position": i
                })
                compressed_password += current_char  # Add only one instance
            else:
                compressed_password += current_char
            
            i += sequence_length
        
        # Calculate adjusted breach time if sequences were found
        adjusted_analysis = None
        if repeating_sequences:
            adjusted_analysis = self.step2_analyze_complexity(compressed_password)
        
        return {
            "has_repeating_sequences": bool(repeating_sequences),
            "repeating_sequences": repeating_sequences,
            "original_length": len(password),
            "compressed_password": compressed_password,
            "compressed_length": len(compressed_password),
            "adjusted_analysis": adjusted_analysis
        }
    
    def generate_final_assessment(self, analysis: Dict) -> Dict:
        """Generate final assessment based on all analysis steps"""
        step1 = analysis["step1_common_check"]
        step2 = analysis["step2_complexity_analysis"]
        step3 = analysis["step3_repeating_sequences"]
        
        # If common password, that's the final result
        if step1["is_common"]:
            return {
                "breach_time": "Instant",
                "breach_explanation": "You are using a well known password!",
                "security_level": "Very Poor",
                "primary_issue": "Common password",
                "recommendations": ["Choose a unique password not found in common password lists"]
            }
        
        # Determine which breach time to use
        if step3["has_repeating_sequences"] and step3["adjusted_analysis"]:
            breach_time = step3["adjusted_analysis"]["breach_time_human"]
            breach_seconds = step3["adjusted_analysis"]["breach_time_seconds"]
            explanation = f"Adjusted for repeating sequences. Effective length: {step3['compressed_length']} characters"
        else:
            breach_time = step2["breach_time_human"]
            breach_seconds = step2["breach_time_seconds"]
            explanation = "Based on full password complexity"
        
        # Determine security level based on breach time in seconds
        if breach_seconds < 1:
            security_level = "Very Poor"
        elif breach_seconds < 3600:  # Less than 1 hour
            security_level = "Poor"
        elif breach_seconds < 86400:  # Less than 1 day
            security_level = "Fair"
        elif breach_seconds < 31536000:  # Less than 1 year
            security_level = "Good"
        else:
            security_level = "Excellent"
        
        # Collect all recommendations
        recommendations = step2["recommendations"].copy() if step2["recommendations"] else []
        if step3["has_repeating_sequences"]:
            recommendations.append("Avoid repeating the same character multiple times in a row")
        
        if not recommendations:
            recommendations = ["Your password looks strong!"]
        
        return {
            "breach_time": breach_time,
            "breach_explanation": explanation,
            "security_level": security_level,
            "recommendations": recommendations,
            "has_repeating_sequences": step3["has_repeating_sequences"],
            "character_groups_used": step2["groups_used"]
        }
    
    def seconds_to_human_readable(self, seconds: float) -> str:
        """Convert seconds to human readable format with cosmic comparisons"""
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            years = seconds / 31536000
            return self.format_years_with_cosmic_context(years)
    
    def format_years_with_cosmic_context(self, years: float) -> str:
        """Format years with cosmic comparisons for perspective"""
        sun_lifespan = 6_000_000_000  # 6 billion years
        universe_age = 13_800_000_000  # 13.8 billion years
        atoms_on_earth_years = 1.33e50  # Reference point for atoms on Earth comparison
        
        if years < 1_000:
            return f"{years:.1f} years"
        elif years < 1_000_000:
            return f"{years/1_000:.1f} thousand years"
        elif years < 1_000_000_000:
            return f"{years/1_000_000:.1f} million years"
        elif years < sun_lifespan:
            return f"{years/1_000_000_000:.1f} billion years"
        elif years < universe_age:
            sun_ratio = years / sun_lifespan
            return f"{years/1_000_000_000:.1f} billion years (⭐ {sun_ratio:.1f} times longer than our sun will exist)"
        elif years < 1_000_000_000_000:  # Less than 1 trillion
            universe_ratio = years / universe_age
            return f"{years/1_000_000_000:.1f} billion years (🌌 {universe_ratio:.1f} times since the Big Bang)"
        elif years < 1_000_000_000_000_000:  # Less than 1 quadrillion
            return f"{years/1_000_000_000_000:.1f} trillion years (🌌 {years/universe_age:.0f} times since the Big Bang)"
        elif years < 1_000_000_000_000_000_000:  # Less than 1 quintillion
            return f"{years/1_000_000_000_000_000:.1f} quadrillion years (🌌 {years/universe_age:.0f} times since the Big Bang)"
        elif years < atoms_on_earth_years:
            return f"{years/1_000_000_000_000_000_000:.1f} quintillion years (🌌 {years/universe_age:.0f} times since the Big Bang)"
        else:
            atoms_ratio = years / atoms_on_earth_years
            if atoms_ratio < 1000:
                return f"{years:.2e} years (🌍 {atoms_ratio:.1f} times more years than atoms on Earth)"
            else:
                return f"{years:.2e} years (🌍 {atoms_ratio:.2e} times more years than atoms on Earth)"
    
    def format_combinations_with_comparisons(self, combinations: int) -> str:
        """Format combinations with real-world comparisons"""
        grains_of_sand = 7.5e18  # 7.5 quintillion grains of sand on Earth
        atoms_on_earth = 1.33e50  # Atoms on Earth
        atoms_in_universe = 1e82   # Atoms in observable universe
        
        if combinations < 1_000:
            return str(int(combinations))
        elif combinations < 1_000_000:
            return f"{combinations/1_000:.1f} thousand"
        elif combinations < 1_000_000_000:
            return f"{combinations/1_000_000:.1f} million"
        elif combinations < 1_000_000_000_000:
            return f"{combinations/1_000_000_000:.1f} billion"
        elif combinations < 1_000_000_000_000_000:
            return f"{combinations/1_000_000_000_000:.1f} trillion"
        elif combinations < 1_000_000_000_000_000_000:
            return f"{combinations/1_000_000_000_000_000:.1f} quadrillion"
        elif combinations < grains_of_sand:
            return f"{combinations/1_000_000_000_000_000_000:.1f} quintillion"
        elif combinations < grains_of_sand * 10:
            sand_ratio = combinations / grains_of_sand
            return f"{combinations/1_000_000_000_000_000_000:.1f} quintillion (🏖️ {sand_ratio:.1f} times more than grains of sand on Earth)"
        elif combinations < atoms_on_earth:
            sand_ratio = combinations / grains_of_sand
            return f"{combinations:.2e} (🏖️ {sand_ratio:.0f} times more than grains of sand on Earth)"
        elif combinations < atoms_in_universe:
            atoms_ratio = combinations / atoms_on_earth
            return f"{combinations:.2e} (🌍 {atoms_ratio:.2e} times more than atoms on Earth)"
        else:
            universe_atoms_ratio = combinations / atoms_in_universe
            return f"{combinations:.2e} (🌌 {universe_atoms_ratio:.2e} times more than atoms in the observable universe)"

# Initialize the password analyzer
analyzer = PasswordAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_password():
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "Password is required"}), 400
    
    try:
        analysis = analyzer.analyze_password(password)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)