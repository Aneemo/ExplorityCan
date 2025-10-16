# ExplorityCan
An attempt to expand on the Can test adding new functionality to Contact manager

## Getting Started

### Prerequisites

- Python 3.x
- pip

### Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/Aneemo/ExplorityCan.git
   ```
2. Navigate to the project directory:
   ```sh
   cd ExplorityCan
   ```
3. Create a virtual environment:
   ```sh
   python -m venv venv
   ```
4. Activate the virtual environment:
   - On Windows:
     ```sh
     .\venv\Scripts\activate
     ```
   - On macOS and Linux:
     ```sh
     source venv/bin/activate
     ```
5. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

### Running the Application

1. Initialize the database:
   ```sh
   flask --app run init-db
   ```
2. Run the application:
   ```sh
   flask --app run run
   ```

The application will be available at `http://127.0.0.1:5000`.