from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

import customtkinter as ctk

from log_analyzer import (
    count_failed_attempts_by_ip,
    detect_brute_force_in_time_window,
    detect_log_format,
    determine_risk_level,
    extract_ip_address,
    find_failed_logins,
    read_log_file,
)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LogSentryApp(ctk.CTk):
    BACKGROUND = "#07111F"
    SIDEBAR = "#0A1728"
    PANEL = "#101F33"
    PANEL_LIGHT = "#14263D"
    BORDER = "#203B59"
    ACCENT = "#17C3B2"
    TEXT = "#F4F7FB"
    MUTED = "#8EA3B8"
    HIGH = "#FF5A67"
    MEDIUM = "#FFB547"
    LOW = "#3DDC97"

    def __init__(self):
        super().__init__()

        self.title("LogSentry - Security Log Analyzer")
        self.geometry("1280x780")
        self.minsize(1050, 680)
        self.configure(fg_color=self.BACKGROUND)

        self.selected_file = None
        self.analysis_results = {}

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.create_sidebar()
        self.create_dashboard()

    def create_sidebar(self):
        sidebar = ctk.CTkFrame(
            self,
            width=230,
            corner_radius=0,
            fg_color=self.SIDEBAR,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(10, weight=1)

        brand = ctk.CTkLabel(
            sidebar,
            text="LOGSENTRY",
            font=ctk.CTkFont(
                family="Helvetica Neue",
                size=23,
                weight="bold",
            ),
            text_color=self.ACCENT,
        )
        brand.grid(row=0, column=0, padx=25, pady=(35, 4), sticky="w")

        brand_description = ctk.CTkLabel(
            sidebar,
            text="SECURITY OPERATIONS",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=self.MUTED,
        )
        brand_description.grid(
            row=1,
            column=0,
            padx=25,
            pady=(0, 35),
            sticky="w",
        )

        navigation_label = ctk.CTkLabel(
            sidebar,
            text="WORKSPACE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=self.MUTED,
        )
        navigation_label.grid(
            row=2,
            column=0,
            padx=25,
            pady=(0, 10),
            sticky="w",
        )

        dashboard_label = ctk.CTkLabel(
            sidebar,
            text="Dashboard",
            height=42,
            anchor="w",
            corner_radius=8,
            fg_color=self.PANEL_LIGHT,
            text_color=self.TEXT,
            padx=14,
        )
        dashboard_label.grid(
            row=3,
            column=0,
            padx=18,
            pady=5,
            sticky="ew",
        )

        self.select_file_button = ctk.CTkButton(
            sidebar,
            text="Select Log File",
            command=self.select_log_file,
            height=42,
            anchor="w",
            corner_radius=8,
            fg_color="transparent",
            hover_color=self.PANEL_LIGHT,
            border_width=1,
            border_color=self.BORDER,
            text_color=self.TEXT,
        )
        rules_label = ctk.CTkLabel(
            sidebar,
            text="DETECTION RULES",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=self.MUTED,
        )

        rules_label.grid(
            row=5,
            column=0,
            padx=25,
            pady=(22, 8),
            sticky="w",
        )

        rules_frame = ctk.CTkFrame(
            sidebar,
            fg_color="transparent",
        )
        rules_frame.grid(
            row=6,
            column=0,
            padx=18,
            sticky="ew",
        )

        rules_frame.grid_columnconfigure((0, 1), weight=1)
        threshold_label = ctk.CTkLabel(
        rules_frame,
            text="Attempts",
            font=ctk.CTkFont(size=10),
            text_color=self.MUTED,
        )

        threshold_label.grid(
            row=0,
            column=0,
            padx=(0, 4),
        )

        window_label = ctk.CTkLabel(
            rules_frame,
            text="Minutes",
            font=ctk.CTkFont(size=10),
            text_color=self.MUTED,
        )

        window_label.grid(
            row=0,
            column=1,
            padx=(4, 0),
        )
        self.threshold_entry = ctk.CTkEntry(
            rules_frame,
            width=82,
            height=34,
            justify="center",
            fg_color=self.BACKGROUND,
            border_color=self.BORDER,
        )

        self.threshold_entry.grid(
            row=1,
            column=0,
            padx=(0, 4),
            pady=(4, 0),
        )

        self.threshold_entry.insert(0, "5")

        self.window_entry = ctk.CTkEntry(
            rules_frame,
            width=82,
            height=34,
            justify="center",
            fg_color=self.BACKGROUND,
            border_color=self.BORDER,
        )

        self.window_entry.grid(
            row=1,
            column=1,
            padx=(4, 0),
            pady=(4, 0),
        )

        self.window_entry.insert(0, "5")


        self.select_file_button.grid(
            row=4,
            column=0,
            padx=18,
            pady=5,
            sticky="ew",
        )

        self.analyze_button = ctk.CTkButton(
            sidebar,
            text="Run Analysis",
            command=self.run_analysis,
            height=42,
            anchor="w",
            corner_radius=8,
            fg_color=self.ACCENT,
            hover_color="#12A89A",
            text_color="#041310",
            state="disabled",
        )
        self.analyze_button.grid(
            row=7,
            column=0,
            padx=18,
            pady=(18, 5),
            sticky="ew",
        )

        clear_button = ctk.CTkButton(
            sidebar,
            text="Clear Results",
            command=self.clear_results,
            height=42,
            anchor="w",
            corner_radius=8,
            fg_color="transparent",
            hover_color=self.PANEL_LIGHT,
            text_color=self.MUTED,
        )
        clear_button.grid(
            row=8,
            column=0,
            padx=18,
            pady=5,
            sticky="ew",
        )

        export_button = ctk.CTkButton(
            sidebar,
            text="Export Report",
            command=self.export_report,
            height=42,
            anchor="w",
            corner_radius=8,
            fg_color="transparent",
            hover_color=self.PANEL_LIGHT,
            text_color=self.MUTED,
        )
        export_button.grid(
            row=9,
            column=0,
            padx=18,
            pady=5,
            sticky="ew",
        )

        footer = ctk.CTkLabel(
            sidebar,
            text="LogSentry v1.0\nLocal Security Analysis",
            justify="left",
            font=ctk.CTkFont(size=10),
            text_color=self.MUTED,
        )
        footer.grid(
            row=11,
            column=0,
            padx=25,
            pady=25,
            sticky="sw",
        )

    def create_dashboard(self):
        dashboard = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=self.BACKGROUND,
        )
        dashboard.grid(row=0, column=1, sticky="nsew")
        dashboard.grid_columnconfigure(0, weight=1)
        dashboard.grid_rowconfigure(3, weight=1)

        self.create_header(dashboard)
        self.create_stat_cards(dashboard)
        self.create_results_area(dashboard)

    def create_header(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, padx=30, pady=(28, 20), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="Security Overview",
            font=ctk.CTkFont(
                family="Helvetica Neue",
                size=28,
                weight="bold",
            ),
            text_color=self.TEXT,
        )
        title.grid(row=0, column=0, sticky="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Analyze authentication logs and identify suspicious activity.",
            font=ctk.CTkFont(size=12),
            text_color=self.MUTED,
        )
        subtitle.grid(row=1, column=0, pady=(5, 0), sticky="w")

        self.status_badge = ctk.CTkLabel(
            header,
            text="  WAITING FOR LOG FILE  ",
            height=30,
            corner_radius=15,
            fg_color=self.PANEL_LIGHT,
            text_color=self.MUTED,
            font=ctk.CTkFont(size=10, weight="bold"),
        )
        self.status_badge.grid(row=0, column=1, rowspan=2, sticky="e")

        self.file_label = ctk.CTkLabel(
            parent,
            text="No file selected",
            anchor="w",
            height=42,
            corner_radius=8,
            fg_color=self.PANEL,
            text_color=self.MUTED,
            padx=15,
        )
        self.file_label.grid(
            row=1,
            column=0,
            padx=30,
            pady=(0, 18),
            sticky="ew",
        )

    def create_stat_cards(self, parent):
        cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        cards_frame.grid(row=2, column=0, padx=30, pady=(0, 18), sticky="ew")

        for column in range(4):
            cards_frame.grid_columnconfigure(column, weight=1)

        card_data = [
            ("TOTAL EVENTS", "total_events", self.ACCENT),
            ("FAILED LOGINS", "failed_logins", self.MEDIUM),
            ("SUSPICIOUS IPS", "suspicious_ips", self.HIGH),
            ("HIGH RISK", "high_risk", self.HIGH),
        ]

        self.stat_labels = {}

        for column, (title, key, color) in enumerate(card_data):
            card = ctk.CTkFrame(
                cards_frame,
                height=110,
                corner_radius=12,
                fg_color=self.PANEL,
                border_width=1,
                border_color=self.BORDER,
            )
            card.grid(
                row=0,
                column=column,
                padx=(0 if column == 0 else 6, 0 if column == 3 else 6),
                sticky="ew",
            )
            card.grid_propagate(False)

            value_label = ctk.CTkLabel(
                card,
                text="0",
                font=ctk.CTkFont(size=30, weight="bold"),
                text_color=color,
            )
            value_label.pack(anchor="w", padx=18, pady=(18, 2))

            title_label = ctk.CTkLabel(
                card,
                text=title,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=self.MUTED,
            )
            title_label.pack(anchor="w", padx=18)

            self.stat_labels[key] = value_label

    def create_results_area(self, parent):
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.grid(row=3, column=0, padx=30, pady=(0, 28), sticky="nsew")
        content.grid_columnconfigure(0, weight=3)
        content.grid_columnconfigure(1, weight=2)
        content.grid_rowconfigure(0, weight=1)

        table_panel = ctk.CTkFrame(
            content,
            corner_radius=12,
            fg_color=self.PANEL,
            border_width=1,
            border_color=self.BORDER,
        )
        table_panel.grid(row=0, column=0, padx=(0, 8), sticky="nsew")
        table_panel.grid_columnconfigure(0, weight=1)
        table_panel.grid_rowconfigure(2, weight=1)

        table_header = ctk.CTkFrame(
            table_panel,
            fg_color="transparent",
        )
        table_header.grid(
            row=0,
            column=0,
            padx=18,
            pady=14,
            sticky="ew",
        )
        table_header.grid_columnconfigure(0, weight=1)

        table_title = ctk.CTkLabel(
            table_header,
            text="IP Risk Analysis",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=self.TEXT,
        )
        table_title.grid(row=0, column=0, sticky="w")

        self.search_entry = ctk.CTkEntry(
            table_header,
            width=170,
            height=32,
            placeholder_text="Search IP address",
            corner_radius=7,
            fg_color=self.BACKGROUND,
            border_color=self.BORDER,
            text_color=self.TEXT,
        )
        self.search_entry.grid(row=0, column=1, padx=(10, 8))
        self.search_entry.bind(
            "<KeyRelease>",
            lambda event: self.update_results_table(),
        )

        self.risk_filter = ctk.CTkOptionMenu(
            table_header,
            values=["All Risks", "HIGH", "MEDIUM", "LOW"],
            command=lambda selected_value: self.update_results_table(),
            width=115,
            height=32,
            corner_radius=7,
            fg_color=self.PANEL_LIGHT,
            button_color=self.BORDER,
            button_hover_color=self.ACCENT,
        )
        self.risk_filter.set("All Risks")
        self.risk_filter.grid(row=0, column=2)

        self.configure_table_style()

        columns = ("ip", "attempts", "risk", "status")

        column_header = ctk.CTkFrame(
            table_panel,
            height=36,
            corner_radius=0,
            fg_color=self.PANEL_LIGHT,
        )
        column_header.grid(
            row=1,
            column=0,
            padx=15,
            sticky="ew",
        )
        column_header.grid_propagate(False)

        header_items = [
            ("IP ADDRESS", 2),
            ("ATTEMPTS", 1),
            ("RISK", 1),
            ("STATUS", 1),
        ]

        for column_index, (header_text, column_weight) in enumerate(
            header_items
        ):
            column_header.grid_columnconfigure(
                column_index,
                weight=column_weight,
            )
            header_label = ctk.CTkLabel(
                column_header,
                text=header_text,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=self.MUTED,
            )
            header_label.grid(
                row=0,
                column=column_index,
                sticky="nsew",
            )

        self.results_table = ttk.Treeview(
            table_panel,
            columns=columns,
            show="",
            style="LogSentry.Treeview",
            takefocus=False,
        )
        self.results_table.bind(
            "<<TreeviewSelect>>",
            self.show_selected_ip_details,
        )

        self.results_table.column("ip", width=170, anchor="w")
        self.results_table.column("attempts", width=90, anchor="center")
        self.results_table.column("risk", width=90, anchor="center")
        self.results_table.column("status", width=130, anchor="center")

        self.results_table.tag_configure("HIGH", foreground=self.HIGH)
        self.results_table.tag_configure("MEDIUM", foreground=self.MEDIUM)
        self.results_table.tag_configure("LOW", foreground=self.LOW)

        self.results_table.grid(
            row=2,
            column=0,
            padx=15,
            pady=(0, 15),
            sticky="nsew",
        )

        alert_panel = ctk.CTkFrame(
            content,
            corner_radius=12,
            fg_color=self.PANEL,
            border_width=1,
            border_color=self.BORDER,
        )
        alert_panel.grid(row=0, column=1, padx=(8, 0), sticky="nsew")
        alert_panel.grid_columnconfigure(0, weight=1)
        alert_panel.grid_rowconfigure(1, weight=1)

        alert_title = ctk.CTkLabel(
            alert_panel,
            text="Security Alerts",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=self.TEXT,
        )
        alert_title.grid(row=0, column=0, padx=18, pady=16, sticky="w")

        self.alert_textbox = ctk.CTkTextbox(
            alert_panel,
            corner_radius=8,
            fg_color=self.BACKGROUND,
            border_width=1,
            border_color=self.BORDER,
            text_color=self.MUTED,
            font=ctk.CTkFont(family="Menlo", size=11),
            wrap="word",
        )
        self.alert_textbox.grid(
            row=1,
            column=0,
            padx=15,
            pady=(0, 15),
            sticky="nsew",
        )
        self.set_alert_text(
            "No active alerts.\n\nSelect a log file to begin analysis."
        )

    def configure_table_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.layout(
            "LogSentry.Treeview",
            [
                (
                    "Treeview.treearea",
                    {"sticky": "nsew"},
                )
            ],
        )

        style.configure(
            "LogSentry.Treeview",
            background=self.BACKGROUND,
            fieldbackground=self.BACKGROUND,
            foreground=self.TEXT,
            rowheight=38,
            borderwidth=0,
            relief="flat",
            bordercolor=self.BACKGROUND,
            lightcolor=self.BACKGROUND,
            darkcolor=self.BACKGROUND,
            font=("Helvetica Neue", 11),
        )

        style.map(
            "LogSentry.Treeview",
            background=[("selected", self.BORDER)],
        )

    def select_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a security log file",
            filetypes=[
                ("Log and text files", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )

        if not file_path:
            return

        self.selected_file = Path(file_path)
        self.file_label.configure(text=str(self.selected_file))
        self.analyze_button.configure(state="normal")
        self.status_badge.configure(
            text="  READY TO ANALYZE  ",
            fg_color=self.PANEL_LIGHT,
            text_color=self.ACCENT,
        )

    def run_analysis(self):
        if self.selected_file is None:
            messagebox.showwarning(
                "No File Selected",
                "Please select a log file before running the analysis.",
            )
            return
        try:
            threshold = int(self.threshold_entry.get())
            window_minutes = int(self.window_entry.get())

            if threshold <= 0 or window_minutes <= 0:
                raise ValueError

        except ValueError:
            messagebox.showerror(
                "Invalid Detection Rules",
                "Attempts and minutes must be positive whole numbers.",
            )
            return

        log_records = read_log_file(self.selected_file)
        log_format = detect_log_format(log_records)
        analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        failed_records = find_failed_logins(log_records)
        ip_attempt_counts = count_failed_attempts_by_ip(failed_records)
        suspicious_ips = detect_brute_force_in_time_window(
            failed_records,
            threshold=threshold,
            window_minutes=window_minutes,
        )

        high_risk_count = sum(
            1
            for count in ip_attempt_counts.values()
            if determine_risk_level(count) == "HIGH"
        )

        self.analysis_results = {
            "total_events": len(log_records),
            "failed_logins": len(failed_records),
            "failed_records": failed_records,
            "ip_attempt_counts": ip_attempt_counts,
            "suspicious_ips": suspicious_ips,
            "high_risk": high_risk_count,
            "log_format": log_format,
            "analysis_time": analysis_time,
            "threshold": threshold,
            "window_minutes": window_minutes,
        }
        self.file_label.configure(
            text=(
                f"{self.selected_file.name}   |   "
                f"Format: {log_format}   |   "
                f"Analyzed: {analysis_time}"
            )
        )

        self.update_stat_cards()
        self.update_results_table()
        self.update_alert_panel()

        self.status_badge.configure(
            text="  ANALYSIS COMPLETE  ",
            fg_color="#103C38",
            text_color=self.ACCENT,
        )

    def update_stat_cards(self):
        self.stat_labels["total_events"].configure(
            text=str(self.analysis_results["total_events"])
        )
        self.stat_labels["failed_logins"].configure(
            text=str(self.analysis_results["failed_logins"])
        )
        self.stat_labels["suspicious_ips"].configure(
            text=str(len(self.analysis_results["suspicious_ips"]))
        )
        self.stat_labels["high_risk"].configure(
            text=str(self.analysis_results["high_risk"])
        )

    def update_results_table(self):
        for item in self.results_table.get_children():
            self.results_table.delete(item)

        if not self.analysis_results:
            return

        ip_attempt_counts = self.analysis_results["ip_attempt_counts"]
        suspicious_ips = self.analysis_results["suspicious_ips"]

        search_query = self.search_entry.get().strip().lower()
        selected_risk = self.risk_filter.get()

        sorted_results = sorted(
            ip_attempt_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        for ip_address, attempt_count in sorted_results:
            risk_level = determine_risk_level(attempt_count)

            if search_query and search_query not in ip_address.lower():
                continue

            if selected_risk != "All Risks" and risk_level != selected_risk:
                continue

            status = (
                "ALERT"
                if ip_address in suspicious_ips
                else "MONITOR"
            )

            self.results_table.insert(
                "",
                "end",
                values=(
                    ip_address,
                    attempt_count,
                    risk_level,
                    status,
                ),
                tags=(risk_level,),
            )

    def show_selected_ip_details(self, event=None):
        selected_items = self.results_table.selection()

        if not selected_items or not self.analysis_results:
            return

        selected_values = self.results_table.item(
            selected_items[0],
            "values",
        )

        if not selected_values:
            return

        ip_address = selected_values[0]
        attempt_count = int(selected_values[1])
        risk_level = selected_values[2]
        status = selected_values[3]

        related_records = [
            record
            for record in self.analysis_results["failed_records"]
            if extract_ip_address(record) == ip_address
        ]

        detail_lines = [
            "IP INVESTIGATION DETAILS",
            "=" * 34,
            f"Source IP: {ip_address}",
            f"Failed attempts: {attempt_count}",
            f"Risk level: {risk_level}",
            f"Status: {status}",
            "",
            "RELATED LOG EVENTS",
            "-" * 34,
        ]

        if related_records:
            for record_number, record in enumerate(
                related_records,
                start=1,
            ):
                detail_lines.append(f"{record_number}. {record}")
        else:
            detail_lines.append("No related log events found.")

        self.set_alert_text("\n\n".join(detail_lines))

    def update_alert_panel(self):
        suspicious_ips = self.analysis_results["suspicious_ips"]
        threshold = self.analysis_results["threshold"]
        window_minutes = self.analysis_results["window_minutes"]

        detection_rule = (
            f"{threshold} failed attempts "
            f"within {window_minutes} minutes"
        )

        if not suspicious_ips:
            self.set_alert_text(
                "ANALYSIS COMPLETED\n\n"
                f"Detection rule: {detection_rule}\n\n"
                "No potential brute-force attacks were detected."
            )
            return

        alerts = [
            "HIGH-PRIORITY SECURITY ALERT",
            "",
            f"Detection rule: {detection_rule}",
            "",
        ]

        for ip_address in suspicious_ips:
            attempt_count = self.analysis_results[
                "ip_attempt_counts"
            ][ip_address]

            alerts.extend(
                [
                    "[BRUTE FORCE]",
                    f"Source IP: {ip_address}",
                    f"Total failed attempts: {attempt_count}",
                    "Risk level: HIGH",
                    "",
                ]
            )

        self.set_alert_text("\n".join(alerts))
        

    def set_alert_text(self, message):
        self.alert_textbox.configure(state="normal")
        self.alert_textbox.delete("1.0", "end")
        self.alert_textbox.insert("1.0", message)
        self.alert_textbox.configure(state="disabled")

    def clear_results(self):
        self.selected_file = None
        self.analysis_results = {}
        self.search_entry.delete(0, "end")
        self.risk_filter.set("All Risks")

        self.file_label.configure(text="No file selected")
        self.analyze_button.configure(state="disabled")

        self.status_badge.configure(
            text="  WAITING FOR LOG FILE  ",
            fg_color=self.PANEL_LIGHT,
            text_color=self.MUTED,
        )

        for label in self.stat_labels.values():
            label.configure(text="0")

        for item in self.results_table.get_children():
            self.results_table.delete(item)

        self.set_alert_text(
            "No active alerts.\n\nSelect a log file to begin analysis."
        )

    def export_report(self):
        if not self.analysis_results:
            messagebox.showwarning(
                "No Analysis Results",
                "Run an analysis before exporting a report.",
            )
            return

        destination = filedialog.asksaveasfilename(
            title="Export security report",
            defaultextension=".txt",
            initialfile="logsentry_security_report.txt",
            filetypes=[("Text files", "*.txt")],
        )

        if not destination:
            return

        report_lines = [
            "LOGSENTRY SECURITY REPORT",
            "=" * 40,
            f"Source file: {self.selected_file}",
            f"Total events: {self.analysis_results['total_events']}",
            f"Failed logins: {self.analysis_results['failed_logins']}",
            "",
            "IP RISK ANALYSIS",
            "-" * 40,
        ]

        for ip_address, attempt_count in sorted(
            self.analysis_results["ip_attempt_counts"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            risk_level = determine_risk_level(attempt_count)
            report_lines.append(
                f"{ip_address:<15} | "
                f"{attempt_count:>3} attempts | "
                f"Risk: {risk_level}"
            )

        report_lines.extend(
            [
                "",
                "POTENTIAL BRUTE-FORCE ATTACKS",
                "-" * 40,
            ]
        )

        suspicious_ips = self.analysis_results["suspicious_ips"]

        if suspicious_ips:
            for ip_address in suspicious_ips:
                report_lines.append(f"ALERT: {ip_address}")
        else:
            report_lines.append("No potential attacks detected.")

        try:
            with open(destination, "w", encoding="utf-8") as report_file:
                report_file.write("\n".join(report_lines))

            messagebox.showinfo(
                "Report Exported",
                "The security report was exported successfully.",
            )

        except OSError as error:
            messagebox.showerror(
                "Export Failed",
                f"The report could not be exported:\n{error}",
            )


def main():
    app = LogSentryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
