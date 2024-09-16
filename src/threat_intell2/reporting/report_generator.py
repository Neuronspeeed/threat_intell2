from ..utils.logging_config import logger

def generate_report(analysis: str) -> None:
    logger.info("START: Reporting and Visualization")
    try:
        with open('report.txt', 'w', encoding='utf-8') as report_file:
            report_file.write(analysis)
        logger.info("END: Reporting and Visualization completed successfully.")
    except Exception as e:
        logger.error(f"ERROR: Reporting and Visualization failed - {e}")