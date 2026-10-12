"""Best-effort report metadata, independent of compliance verdicts."""
import os
import re
import pdfplumber


def collect_metadata(cfg, driver):
    vendor = cfg['target'].get('driver', '')
    database = {'product': {'oracle': 'Oracle Database', 'sqlserver': 'Microsoft SQL Server',
                            'mssql': 'Microsoft SQL Server'}.get(vendor, 'Unknown'),
                'name': 'Unknown', 'version': 'Unknown'}
    cursor = None
    try:
        if vendor == 'oracle':
            database['version'] = str(driver.conn.version or 'Unknown')
            cursor = driver.conn.cursor()
            cursor.execute("SELECT SYS_CONTEXT('USERENV', 'DB_NAME') FROM DUAL")
            row = cursor.fetchone()
            if row:
                database['name'] = str(row[0] or 'Unknown')
        elif vendor in ('sqlserver', 'mssql'):
            cursor = driver.conn.cursor()
            cursor.execute("SELECT DB_NAME(), CAST(SERVERPROPERTY('ProductVersion') AS varchar(128))")
            row = cursor.fetchone()
            if row:
                database.update(name=str(row[0] or 'Unknown'), version=str(row[1] or 'Unknown'))
    except Exception:
        # Missing metadata privileges must never interrupt the audit.
        pass
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass

    path = cfg.get('audit', {}).get('benchmark_pdf', '')
    benchmark = {'name': 'Unknown', 'version': 'Unknown', 'file': os.path.basename(path)}
    if path:
        try:
            with pdfplumber.open(path) as pdf:
                text = ' '.join((page.extract_text() or '') for page in pdf.pages[:2])
            text = re.sub(r'\s+', ' ', text)
            title = re.search(r'\bCIS\s+(.+?\bBenchmark)\b', text, re.I)
            if title:
                benchmark['name'] = title.group(0)
                version = re.search(r'\bv?(\d+\.\d+\.\d+)\b', text[title.end():], re.I)
                if version:
                    benchmark['version'] = version.group(1)
        except Exception:
            pass
    return {'database': database, 'benchmark': benchmark}