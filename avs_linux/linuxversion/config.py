# config.py
import configparser

class ScannerConfig:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")

    @property
    def output_format(self):
        return self.config.get("general", "output_format", fallback="txt")

    @property
    def output_filename(self):
        return self.config.get("general", "output_filename", fallback="report")

    @property
    def encrypt_output(self):
        return self.config.getboolean("general", "encrypt_output", fallback=False)

    @property
    def amass_enabled(self):
        return self.config.getboolean("osint", "amass", fallback=True)

    @property
    def whois_enabled(self):
        return self.config.getboolean("osint", "whois", fallback=True)

    @property
    def nmap_enabled(self):
        return self.config.getboolean("scans", "nmap", fallback=True)

    @property
    def zap_enabled(self):
        return self.config.getboolean("scans", "zap", fallback=True)

    @property
    def zap_api_key(self):
        return self.config.get("zap", "api_key", fallback=None)

    @property
    def zap_path(self):
    	return self.config.get("zap", "zap_path")

    @property
    def time_interval(self):
        return self.config.getint("schedule", "time_interval", fallback=None)
