# py365: A Daily Exploration of Python Applications

A repository documenting a 365-day challenge to write and publish a new Python script daily. This project serves as a practical exploration of Python's versatility across various domains in software engineering and data science.

---

## 📋 Abstract

The **py365** project is a year-long commitment to hands-on learning and development. Each day, a new, self-contained Python script will be added, focusing on a specific problem or technology. The topics will span a wide spectrum, from low-level system automation and algorithmic challenges to high-level machine learning models and web application components. This repository aims to become a comprehensive logbook of applied Python programming.

---

## 🎯 Technical Objectives

The primary goals of this initiative are:
* **Skill Reinforcement:** Solidify core Python knowledge and master the standard library.
* **Ecosystem Exploration:** Gain practical experience with popular third-party libraries and frameworks (e.g., NumPy, Pandas, Scikit-learn, Flask, FastAPI).
* **Domain Versatility:** Apply Python to solve problems in diverse fields such as DevOps, Machine Learning, Automation, and Web Development.
* **Best Practices:** Adhere to modern software development principles, including code linting, documentation, and version control.

---

## 🛠️ Technology Stack

While individual scripts will have unique dependencies, the core technologies used throughout this project include:

* **Language:** Python 3.10+
* **Key Libraries:**
    * **Data Science & ML:** NumPy, Pandas, Scikit-learn, Matplotlib
    * **Web Development:** Flask, FastAPI, Requests, Beautiful Soup
    * **Automation & DevOps:** Subprocess, OS, shutil, Fabric
* **Tools:** Git, Pip, venv
* **Code Quality:** Black (formatter), Flake8 (linter)

---

## 📂 Repository Structure

All code is maintained in the `apps/` directory. A flat hierarchy is used to simplify navigation, with each script following a strict naming convention:

**`YYYY-MM-DD--descriptive-name.py`**

This convention makes each script easily identifiable by its creation date and purpose.

```
py365/
└── apps/
    ├── 2025-09-17--sha256-file-hasher.py
    ├── 2025-09-18--rest-api-health-checker.py
    ├── 2025-09-19--image-resizer-utility.py
    └── ...
```

---

## ⚙️ Installation and Setup

To run the scripts in this repository, it is recommended to set up a local virtual environment.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourUsername/py365.git](https://github.com/YourUsername/py365.git)
    cd py365
    ```

2.  **Create and activate a virtual environment:**
    * On macOS/Linux:
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    * On Windows:
        ```bash
        python -m venv venv
        .\venv\Scripts\activate
        ```

3.  **Install dependencies:**
    Many scripts will rely on third-party packages. A `requirements.txt` file will be maintained with common dependencies.
    ```bash
    pip install -r requirements.txt
    ```
    *Note: Individual scripts may have special dependencies listed in their docstrings.*

---

## ▶️ Usage

Navigate to the `apps` directory and execute any script using the Python interpreter. Most scripts are designed to be run directly from the command line.

**Example:**
```bash
# Navigate to the scripts directory
cd apps/

# Run a specific script
python 2025-09-17--sha256-file-hasher.py --file my_document.txt
```

Please read the docstring or comments at the top of each script file for specific usage instructions and required arguments.

---

## ✨ Code Principles

* **Clarity:** Code is written to be as readable and self-documenting as possible.
* **Modularity:** Scripts are self-contained and aim to perform one task well.
* **PEP 8:** Code formatting adheres to the PEP 8 style guide.
* **Documentation:** Each script includes a docstring explaining its purpose, arguments, and usage.

---

## 🤝 Contributing

While this is a personal project, suggestions and bug reports are welcome. Please feel free to open an issue to discuss improvements or report a problem.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.