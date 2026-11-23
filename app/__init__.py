"""VulnForge local vulnerability reproduction workflow."""

from dotenv import load_dotenv


# Keep local credentials in the ignored project-root .env file. Existing
# process environment variables take precedence over values from that file.
load_dotenv()
