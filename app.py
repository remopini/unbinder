#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os
import dns.resolver
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for flashing messages
DB_PATH = 'records.db'
UNBOUND_CONFIG_PATH = '/etc/unbound/unbound.conf.d/local-data.conf'

def restart_unbound():
    """Safely restart the unbound service using systemctl."""
    try:
        # First check if the config is valid
        subprocess.run(['unbound-checkconf'], check=True)
        # If config is valid, restart the service
        subprocess.run(['systemctl', 'restart', 'unbound'], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error restarting unbound: {e}")
        return False

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                resolved_ip TEXT
            )
        ''')

def get_records():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT id, domain, type, value, ttl, resolved_ip FROM records')
        rows = cursor.fetchall()
        # Convert to list of dicts for easier template handling
        return [dict(r) for r in rows]

def resolve_cname(cname_target):
    """Resolve a CNAME target to its final A record IP address."""
    try:
        resolver = dns.resolver.Resolver()
        # First try to resolve the CNAME chain to get the final hostname
        try:
            cname_answers = resolver.resolve(cname_target, 'CNAME')
            # If there's a CNAME record, follow it
            for rdata in cname_answers:
                cname_target = str(rdata.target).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # No CNAME record, try resolving A record directly
        
        # Now resolve the A record
        answers = resolver.resolve(cname_target, 'A')
        return str(answers[0])  # Return the first IP address
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
        raise ValueError(f"Could not resolve {cname_target}: {str(e)}")

def refresh_cname_resolutions():
    """Re-resolve all CNAME records and store their resolved IPs.
    If a CNAME cannot be resolved, its resolved_ip is set to NULL.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, value FROM records WHERE type = 'CNAME'")
        cnames = cursor.fetchall()
        for cid, target in cnames:
            try:
                ip = resolve_cname(target)
            except Exception:
                ip = None
            cursor.execute('UPDATE records SET resolved_ip = ? WHERE id = ?', (ip, cid))
        conn.commit()

def generate_unbound_config():
    # Refresh CNAME resolutions so generated config is up-to-date
    refresh_cname_resolutions()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT domain, type, value, ttl, resolved_ip FROM records')
        records = cursor.fetchall()

        config_lines = []
        config_lines.append('server:')
        config_lines.append('\tlocal-zone: "avexys.com." transparent')
        for domain, record_type, value, ttl, resolved_ip in records:
            if record_type == 'A':
                config_lines.append(f'\tlocal-data: "{domain} {ttl} IN A {value}"')
            elif record_type == 'CNAME' and resolved_ip:
                # For CNAME records, write an A record using the resolved IP
                config_lines.append(f'\tlocal-data: "{domain} {ttl} IN A {resolved_ip}"')

    with open(UNBOUND_CONFIG_PATH, 'w') as f:
        f.write('\n'.join(config_lines) + '\n')
    
    restart_unbound()

@app.route('/')
def index():
    records = get_records()

    # Group A records and attach any CNAME aliases that resolve to the same IP
    a_records = [r for r in records if r['type'] == 'A']
    cname_records = [r for r in records if r['type'] == 'CNAME']

    # Build alias list: for each A record, find CNAMEs whose resolved_ip == A.value
    for a in a_records:
        a['aliases'] = [c['domain'] for c in cname_records if c.get('resolved_ip') == a['value']]

    # Also collect standalone CNAMEs that don't map to any A record
    mapped_cnames = set()
    for a in a_records:
        mapped_cnames.update(a['aliases'])
    unmapped_cnames = [c for c in cname_records if c['domain'] not in mapped_cnames]

    return render_template('index.html', a_records=a_records, cname_records=unmapped_cnames)

@app.route('/add', methods=['POST'])
def add_record():
    try:
        domain = request.form['domain'].strip()
        record_type = request.form['type']
        value = request.form['value'].strip()
        ttl = int(request.form['ttl'])

        if not all([domain, record_type, value, str(ttl)]):
            flash('All fields are required', 'error')
            return redirect(url_for('index'))

        if record_type not in ['A', 'CNAME']:
            flash('Invalid record type', 'error')
            return redirect(url_for('index'))

        resolved_ip = None
        # Prevent duplicate A record IPs
        if record_type == 'A':
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM records WHERE type = 'A' AND value = ?", (value,))
                if cur.fetchone():
                    flash('An A record with this IP already exists', 'error')
                    return redirect(url_for('index'))

        if record_type == 'CNAME':
            try:
                resolved_ip = resolve_cname(value)
            except ValueError as e:
                flash(f'Error resolving CNAME: {str(e)}', 'error')
                return redirect(url_for('index'))

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO records (domain, type, value, ttl, resolved_ip) VALUES (?, ?, ?, ?, ?)',
                (domain, record_type, value, ttl, resolved_ip)
            )
        
        generate_unbound_config()
        flash('Record added successfully', 'success')

    except ValueError as e:
        flash(f'Invalid TTL value: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')

    return redirect(url_for('index'))


@app.route('/edit/<int:record_id>', methods=['GET', 'POST'])
def edit_record(record_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT id, domain, type, value, ttl FROM records WHERE id = ?', (record_id,))
        row = cursor.fetchone()
        if not row:
            flash('Record not found', 'error')
            return redirect(url_for('index'))

    if request.method == 'GET':
        record = dict(row)
        return render_template('edit.html', record=record)

    # POST -> update
    try:
        domain = request.form['domain'].strip()
        record_type = request.form['type']
        value = request.form['value'].strip()
        ttl = int(request.form['ttl'])

        if record_type not in ['A', 'CNAME']:
            flash('Invalid record type', 'error')
            return redirect(url_for('index'))

        resolved_ip = None
        # If setting to A, ensure no other A has same IP
        if record_type == 'A':
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM records WHERE type = 'A' AND value = ? AND id != ?", (value, record_id))
                if cur.fetchone():
                    flash('Another A record with this IP already exists', 'error')
                    return redirect(url_for('index'))

        if record_type == 'CNAME':
            try:
                resolved_ip = resolve_cname(value)
            except ValueError as e:
                flash(f'Error resolving CNAME: {str(e)}', 'error')
                return redirect(url_for('index'))

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE records SET domain = ?, type = ?, value = ?, ttl = ?, resolved_ip = ? WHERE id = ?',
                (domain, record_type, value, ttl, resolved_ip, record_id)
            )

        generate_unbound_config()
        flash('Record updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating record: {str(e)}', 'error')

    return redirect(url_for('index'))

@app.route('/delete/<int:record_id>', methods=['POST'])
def delete_record(record_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM records WHERE id = ?', (record_id,))
            
        generate_unbound_config()
        flash('Record deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting record: {str(e)}', 'error')

    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    if not os.path.exists('templates'):
        os.makedirs('templates')
    app.run(host='0.0.0.0', port=80)