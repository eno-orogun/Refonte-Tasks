from flask import Flask, request, jsonify, render_template
import os
import random
import string

app = Flask(__name__)
# Use environment variable or random generation for secret key (avoids hardcoding)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=24)))

# Mock database (tasks list)
tasks = []

@app.route('/')
def home():
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['POST'])
def add_task():
    task_content = request.form.get('content')  # Get user input
    if task_content:
        # Input validation to prevent XSS
        task_content = task_content.strip()  # Remove unnecessary whitespace
        if len(task_content) > 0:
            tasks.append(task_content)
            return jsonify({"message": "Task added successfully!"}), 200
        else:
            return jsonify({"error": "Content cannot be empty!"}), 400
    return jsonify({"error": "Content cannot be empty!"}), 400

@app.route('/delete', methods=['POST'])
def delete_task():
    try:
        task_index = request.form.get('index')
        # Validate the index to ensure it is an integer and within range
        if task_index is None:
            return jsonify({"error": "Index is required!"}), 400
        task_index = int(task_index)
        if 0 <= task_index < len(tasks):
            tasks.pop(task_index)
            return jsonify({"message": "Task deleted successfully!"}), 200
        else:
            return jsonify({"error": "Invalid task index!"}), 400
    except ValueError:
        return jsonify({"error": "Invalid index format!"}), 400
    except Exception as e:
        # Handle any unexpected exceptions gracefully
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    # In production, never use debug=True
    app.run(debug=False)
 
