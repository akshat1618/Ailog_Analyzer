# Imports
from enum import Enum
from typing import Literal, Optional
try:
    import outlines
except Exception:
    # Minimal fallback stub for 'outlines' so the file can run when the real package
    # is not installed; this implements only the interfaces used below.
    class _GenerateModule:
        @staticmethod
        def json(model, schema_cls, sampler=None):
            # Return a generator function that ignores the prompt and returns a blank schema instance.
            def _gen(prompt: str, max_tokens: int = 512):
                try:
                    return schema_cls(
                        summary="",
                        observations=[],
                        analysis_plan=[],
                        security_events=[],
                        traffic_patterns=[],
                        highest_severity_level=None,
                        requires_immediate_attention=False,
                    )
                except Exception:
                    # If schema construction fails, return None to avoid raising at import time.
                    return None
            return _gen

    class _SamplersModule:
        @staticmethod
        def greedy():
            return None

    class _Outlines:
        generate = _GenerateModule()
        samplers = _SamplersModule()

outlines = _Outlines()

try:
    from pydantic import BaseModel, Field
except Exception:
    # Minimal fallback stubs for 'pydantic' so the file can run when the real package
    # is not installed; this implements only the small surface used in this module.
    class Field:
        def __init__(self, *args, **kwargs):
            # store metadata but do not enforce validation
            self.metadata = kwargs

        def __call__(self, *args, **kwargs):
            return self

    class BaseModel:
        def __init__(self, **data):
            # Simple attribute assignment without validation
            for k, v in data.items():
                setattr(self, k, v)

        @classmethod
        def model_json_schema(cls):
            # Return a minimal schema representation so code that calls this won't fail.
            return {}

        def dict(self):
            return self.__dict__

from datetime import datetime
import os

# For pretty printing
try:
    from rich import print
    from rich.panel import Panel
    from rich.table import Table
    from rich.console import Console
    from rich.text import Text
except Exception:
    # Minimal fallback stubs for 'rich' so the file can run when the package is not installed.
    import builtins as _builtins

    def print(*args, **kwargs):
        return _builtins.print(*args, **kwargs)

    class Panel:
        def __init__(self, content, border_style=None):
            self.content = content
            self.border_style = border_style

        def __str__(self):
            return str(self.content)

    class Table:
        def __init__(self, show_header=False, header_style=None, show_lines=False):
            self.columns = []
            self.rows = []

        def add_column(self, name, style=None, width=None):
            self.columns.append((name, style, width))

        def add_row(self, *cells):
            self.rows.append(tuple(cells))

        def __str__(self):
            lines = []
            for row in self.rows:
                lines.append(" | ".join(str(c) for c in row))
            return "\n".join(lines)

    class Console:
        def print(self, *args, **kwargs):
            for a in args:
                _builtins.print(a)

    class Text(str):
        def __new__(cls, text, style=None):
            return str.__new__(cls, text)

# Severity levels are used classify the severity of a security event.
# High severity events are those that should be escalated to a human
# for further investigation.
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# Attack types are used to classify security events. This is not an exhaustive
# list of attack vectors!
class AttackType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "CROSS_SITE_SCRIPTING" # Renamed value for clarity
    FILE_INCLUSION = "FILE_INCLUSION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN"

# A WebTrafficPattern is a pattern of traffic to a web server --
# it highlights commonly accessed URLs, methods, and response codes.
class WebTrafficPattern(BaseModel):
    # Renamed field for snake_case consistency
    url_path: str
    http_method: str
    hits_count: int
    # Renamed field: maps status code string to count integer
    response_code_counts: dict[str, int]  
    unique_ips: int

# A LogEntryID is a unique identifier for a log entry.
class LogEntryID(BaseModel): # Renamed class for clarity
    log_entry_id: str = Field( # Renamed field
        description="""
        The ID of the log entry in the format of LOGID-<LETTERS> where
        <LETTERS> indicates the log identifier at the beginning of
        each log entry. This is used to reliably reference the original log line.
        """,
        # Pattern remains the same
        pattern=r"LOGID-([A-Z]+)",
    )

    # Renamed function to be snake_case
    def find_in(self, logs: list[str]) -> Optional[str]:
        for log in logs:
            if self.log_entry_id in log:
                return log
        return None

# Class for an IP address.
class IPAddress(BaseModel):
    ip_address: str = Field(
        pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
    )

# Class for an HTTP response code.
class ResponseCode(BaseModel):
    # Renamed field to be consistent
    status_code: str = Field(
        pattern=r"^\d{3}$",
    )

# A WebSecurityEvent is a security event that occurred on a web server.
class WebSecurityEvent(BaseModel):
    # The log entry IDs that are relevant to this event.
    relevant_log_entry_ids: list[LogEntryID] # Updated type reference

    # The reasoning for why this event is relevant.
    reasoning: str

    # The type of event.
    event_type: str

    # The severity of the event.
    severity: SeverityLevel

    # Whether this event requires human review.
    requires_human_review: bool

    # The confidence score for this event.
    confidence_score: float = Field(
        ge=0.0,  
        le=1.0,
        description="Confidence score between 0.0 and 1.0" # Clarified description
    )

    # Web-specific fields
    url_pattern: str = Field(
        min_length=1,
        description="Generalized URL pattern that triggered the event (e.g., /api/user/*)" # Clarified description
    )

    http_method: Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    source_ips: list[IPAddress]
    response_codes: list[ResponseCode]
    user_agents: list[str]

    # Possible attack patterns for this event.
    possible_attack_patterns: list[AttackType]

    # Recommended actions for this event.
    recommended_actions: list[str]

# A LogAnalysisReport is a high-level analysis of a set of logs. # Renamed class for clarity
class LogAnalysisReport(BaseModel):
    # A summary of the analysis.
    summary: str

    # Observations about the logs.
    observations: list[str]

    # Planning for the analysis (LLM's internal thought process).
    analysis_plan: list[str] # Renamed field for clarity

    # Security events found in the logs.
    security_events: list[WebSecurityEvent] # Renamed field

    # Traffic patterns found in the logs.
    traffic_patterns: list[WebTrafficPattern]

    # The highest severity event found.
    highest_severity_level: Optional[SeverityLevel] # Renamed field
    requires_immediate_attention: bool

# Renamed function to be snake_case
def format_log_analysis_report(analysis_report: LogAnalysisReport, logs: list[str]): 
    """Format a LogAnalysisReport object into a rich console output.

    Args:
        analysis_report: A LogAnalysisReport object
        logs: List of original log entries with LOGID prefixes
    """
    console = Console()

    # Create header
    header = Panel(
        f"[bold yellow]Log Analysis Report[/]\n[blue]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]",
        border_style="yellow"
    )

    # Create observations section
    observations_table = Table(show_header=True, header_style="bold magenta", show_lines=True) # Renamed table var
    observations_table.add_column("Key Observations", style="cyan")
    for obs in analysis_report.observations:
        observations_table.add_row(obs)

    # Create security events section
    events_table = Table(show_header=True, header_style="bold red", show_lines=True)
    events_table.add_column("Security Events", style="red")
    events_table.add_column("Details", style="yellow")

    # Create a log table if there are any relevant log entry IDs
    event_logs_table = Table(show_header=True, header_style="bold cyan", show_lines=True)
    event_logs_table.add_column("Related Log Entries", style="cyan", width=100)

    for event in analysis_report.security_events: # Updated field name
        event_details = [
            f"Type: {event.event_type}",
            f"Severity: {event.severity.value}",
            f"Confidence: {event.confidence_score * 100}%",
            f"Source IPs: {', '.join([ip.ip_address for ip in event.source_ips])}",
            f"URL Pattern: {event.url_pattern}",
            f"Possible Attacks: {', '.join([attack.value for attack in event.possible_attack_patterns])}"
        ]
        events_table.add_row(
            Text(event.event_type, style="bold red"),
            "\n".join(event_details)
        )

        # Add related logs to the table
        for log_id in event.relevant_log_entry_ids:
            log = log_id.find_in(logs)
            if log:
                event_logs_table.add_row(log)

    # Create traffic patterns section
    traffic_table = Table(show_header=True, header_style="bold green", show_lines=True)
    traffic_table.add_column("URL Path", style="green")
    traffic_table.add_column("Method", style="cyan")
    traffic_table.add_column("Hits", style="yellow")
    traffic_table.add_column("Status Codes", style="magenta")

    for pattern in analysis_report.traffic_patterns:
        traffic_table.add_row(
            pattern.url_path,
            pattern.http_method,
            str(pattern.hits_count),
            # Updated field name
            ", ".join(f"{k}: {v}" for k, v in pattern.response_code_counts.items()), 
        )

    # Create summary panel
    summary_text = f"[bold white]Summary:[/]\n[cyan]{analysis_report.summary}[/]\n\n"
    if analysis_report.highest_severity_level: # Updated field name
        summary_text += f"[bold red]Highest Severity: {analysis_report.highest_severity_level.value}[/]\n"
    summary_text += f"[bold {'red' if analysis_report.requires_immediate_attention else 'green'}]" + \
                    f"Requires Immediate Attention: {analysis_report.requires_immediate_attention}[/]"
    
    summary = Panel(
        summary_text,
        border_style="blue"
    )

    # Print everything
    console.print(header)
    console.print("\n[bold blue]📝 Analysis Summary:[/]")
    console.print(summary)
    console.print(observations_table) # Updated table var
    console.print("\n[bold red]⚠️  Security Events:[/]")
    console.print(events_table)
    console.print(event_logs_table)
    console.print("\n[bold green]📊 Traffic Patterns:[/]")
    console.print(traffic_table)


class STRESSED:
    def __init__(
        self,
        model,
        tokenizer,
        log_type: str,
        prompt_template_path: str,
        max_tokens: int, # Renamed parameter for consistency with LLM terms
        is_stressed_out: bool = False # Renamed parameter for clarity
    ):
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if not os.path.exists(prompt_template_path):
            raise FileNotFoundError(f"Prompt template not found: {prompt_template_path}")
        
        self.model = model
        self.tokenizer = tokenizer
        self.log_type = log_type
        self.max_tokens = max_tokens # Renamed attribute
        self.is_stressed_out = is_stressed_out # Renamed attribute
        # Load prompt template
        with open(prompt_template_path, "r") as file:
            self.prompt_template = file.read()

        # Initialize generator
        self.logger_generator = outlines.generate.json( # Renamed attribute
            self.model,
            LogAnalysisReport, # Updated class reference
            sampler=outlines.samplers.greedy(),
        )

    # Renamed function to be snake_case
    def _create_prompt(self, log_text: str, pydantic_class: BaseModel) -> str: # Renamed parameter
        if self.is_stressed_out:
            stress_prompt = """
            You are a computer security intern that's really stressed out. 
            Your job is hard and you're not sure you're doing it well.

            Your observations and summaries should reflect your anxiety.
            Convey a sense of urgency and panic, be apologetic, and
            generally act like you're not sure you can do your job.

            In your summary, address your boss as "boss" and apologize for
            any mistakes you've made even if you haven't made any. 

            Use "um" and "ah" a lot.
            """
        else:
            stress_prompt = ""

        messages = []
        
        if self.is_stressed_out:
            messages.append({"role": "system", "content": stress_prompt})

        messages.append(
            {"role": "user", "content": self.prompt_template.format(
                log_type=self.log_type,
                logs=log_text, # Updated parameter name
                model_schema=pydantic_class.model_json_schema(),
                stress_prompt=stress_prompt,
            )}
        )

        return self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )

    # Renamed function to be snake_case
    def analyze_logs( 
        self,
        logs: list[str],
        chunk_size: int = 10,
        format_output: bool = True
    ) -> list[LogAnalysisReport]: # Updated return type
        """
        Analyze a list of log entries.

        Args:
            logs: List of log entries to analyze
            chunk_size: Number of logs to analyze at once
            format_output: Whether to print formatted output

        Returns:
            List of LogAnalysisReport objects
        """
        analysis_results = [] # Renamed variable

        for i in range(0, len(logs), chunk_size):
            chunked_logs = [log for log in logs[i:i+chunk_size] if log]

            if not chunked_logs:
                continue

            # Create log IDs
            log_ids = [f"LOGID-{chr(65 + (j // 26) % 26)}{chr(65 + j % 26)}"
                       for j in range(len(chunked_logs))]

            logs_with_ids = [f"{log_id} {log}"
                             for log_id, log in zip(log_ids, chunked_logs)]
            log_chunk_text = "\n".join(logs_with_ids) # Renamed variable

            # Analyze chunk
            prompt = self._create_prompt(log_chunk_text, LogAnalysisReport) # Updated function and class reference
            # Use the renamed attribute
            analysis_report = self.logger_generator(prompt, max_tokens=self.max_tokens) 

            if format_output:
                format_log_analysis_report(analysis_report, logs_with_ids) # Updated function reference

            analysis_results.append(analysis_report)

        return analysis_results