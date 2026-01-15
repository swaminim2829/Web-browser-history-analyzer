import os
import logging
import sqlite3
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import base64

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

API_KEY = "ff3577da16a1d6d279b3495fc391b767ca3d9c9907f4988bab28f335c5d4bf15"  # Replace with your VirusTotal API key


def resolve_base_path(browser_name):
    if os.name == 'nt':  # Windows
        if browser_name == "Chrome":
            return os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Profile 4")
        elif browser_name == "Firefox":
            return os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
        elif browser_name == "Edge":
            return os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default")
    else:  # Linux/MacOS
        if browser_name == "Chrome":
            return str(Path.home() / ".config" / "google-chrome" / "Default")
        elif browser_name == "Firefox":
            return str(Path.home() / ".mozilla" / "firefox")
        elif browser_name == "Edge":
            return str(Path.home() / ".config" / "microsoft-edge" / "Default")
    return None


def fetch_data(db_path, sql_query):
    if not os.path.exists(db_path):
        logging.warning(f"Database not found: {db_path}")
        return []
    try:
        temp_db_path = db_path + "_copy"
        with open(db_path, 'rb') as original, open(temp_db_path, 'wb') as copy:
            copy.write(original.read())
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        cursor.execute(sql_query)
        columns = [desc[0] for desc in cursor.description]
        data = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        os.remove(temp_db_path)
        return data
    except Exception as e:
        logging.error(f"Error fetching data from {db_path}: {e}")
        return []


def scan_url_with_virustotal(url):
    """Scan the selected URL using VirusTotal API."""
    try:
        headers = {"x-apikey": API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            malicious = json_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = json_response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            harmless = json_response["data"]["attributes"]["last_analysis_stats"]["harmless"]
            return f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}"
        else:
            return f"Error: Unable to scan URL. Status code {response.status_code}"
    except Exception as e:
        logging.error(f"Error checking URL with VirusTotal: {e}")
        return "Error: Unable to scan URL."


def extract_browser_history(browser_name, query):
    """Extract browser history data."""
    base_path = resolve_base_path(browser_name)
    if not base_path:
        logging.warning(f"Base path for {browser_name} not found.")
        return []

    db_path = os.path.join(base_path, query["db"])
    data = fetch_data(db_path, query["sql"])
    return data


def display_data_in_gui(data):
    """Display the extracted data in a Tkinter GUI with a scan button."""
    if not data:
        messagebox.showinfo("No Data", "No data found to display.")
        return

    def scan_selected_url():
        """Scan the selected URL from the Treeview."""
        selected_item = tree.focus()
        if not selected_item:
            messagebox.showinfo("No Selection", "Please select a URL to scan.")
            return

        selected_url = tree.item(selected_item, "values")[0]  # Assuming the first column contains the URL
        scan_result = scan_url_with_virustotal(selected_url)
        messagebox.showinfo("Scan Result", f"Scan result for {selected_url}:\n{scan_result}")

    root = tk.Tk()
    root.title("Browser History Viewer")

    frame = ttk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True)

    columns = list(data[0].keys())
    tree = ttk.Treeview(frame, columns=columns, show="headings")

    scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
    tree.configure(yscrollcommand=scrollbar_y.set)

    scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
    scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
    tree.configure(xscrollcommand=scrollbar_x.set)

    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=150, anchor=tk.W)

    for row in data:
        tree.insert("", tk.END, values=[row[col] for col in columns])

    tree.pack(fill=tk.BOTH, expand=True)

    scan_button = ttk.Button(root, text="Scan Selected URL", command=scan_selected_url)
    scan_button.pack(pady=10)

    root.mainloop()


def main():
    """Main function for browser history extraction."""
    logging.info("Starting Browser History Analysis...")

    queries = {
        "Chrome": {
            "db": "History",
            "sql": "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100",
        },
        "Firefox": {
            "db": "places.sqlite",
            "sql": "SELECT url, title, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 100",
        },
    }

    browser_name = "Chrome"  # Change this to "Firefox" or "Edge" as needed
    query = queries.get(browser_name)

    if query:
        data = extract_browser_history(browser_name, query)
        display_data_in_gui(data)
    else:
        logging.error(f"No queries defined for {browser_name}.")


if __name__ == "__main__":
    main()