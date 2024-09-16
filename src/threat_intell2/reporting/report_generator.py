from ..utils.logging_config import logger
import os
from ..config import OUTPUTS_DIR

def generate_report(analysis: str, timestamp: str) -> None:
    logger.info("START: Reporting and Visualization")
    try:
        report_path = os.path.join(OUTPUTS_DIR, f'report_{timestamp}.txt')
        with open(report_path, 'w', encoding='utf-8') as report_file:
            report_file.write(analysis)
        logger.info(f"Report generated and saved to {report_path}")
        logger.info("END: Reporting and Visualization completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Reporting and Visualization failed - {e}")