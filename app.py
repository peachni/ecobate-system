from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import psycopg2, re, os, datetime
from psycopg2.extras import RealDictCursor
from psycopg2 import InternalError 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from decimal import Decimal
import uuid

app = Flask(__name__)
app.secret_key = "ftmk_utem_psm_final_secure_key_2024"
UPLOAD_FOLDER = 'static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- DATABASE CONNECTION ---
def get_db_connection():
    # This will check Render's environment variables first, falling back to localhost if running locally
    conn = psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        database=os.environ.get("DB_NAME", "ecobate"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD", "admin1234"),
        port=os.environ.get("DB_PORT", "5432")
    )
    return conn

# --- SECURITY: PASSWORD STRENGTH ---
def is_strong_password(password):
    if len(password) < 8: return False
    if not re.search("[a-z]", password): return False
    if not re.search("[A-Z]", password): return False
    if not re.search("[0-9]", password): return False
    if not re.search("[@#$%^&+=!]", password): return False
    return True

# --- 0. HOME DASHBOARD ---
@app.route('/')
def index():
    if 'user_id' not in session: return render_template('index.html')
    if session.get('role') == 'ADMIN': return redirect(url_for('admin_dashboard'))
    elif session.get('role') == 'COLLECTOR': return redirect(url_for('tasks'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Fetch Live Market Rates for Seller
    cur.execute('SELECT * FROM price_setting ORDER BY grade_name ASC')
    prices = cur.fetchall()

    cur.execute('SELECT balance FROM wallet WHERE user_id = %s', (session['user_id'],))
    wallet = cur.fetchone()
    
    cur.execute('SELECT qr_code_token FROM seller WHERE user_id = %s', (session['user_id'],))
    qr = cur.fetchone()

    # Calculate CO2 Saved
    cur.execute("""
        SELECT COALESCE(SUM(cd.liters), 0) as total_liters 
        FROM collection_detail cd 
        JOIN collection_request cr ON cd.request_id = cr.request_id 
        WHERE cr.seller_id = %s
    """, (session['user_id'],))
    res_liters = cur.fetchone()
    co2_saved = float(res_liters['total_liters']) * 2.5
    
    cur.execute("""
        SELECT cr.*, cd.total_payout FROM collection_request cr 
        LEFT JOIN collection_detail cd ON cr.request_id = cd.request_id 
        WHERE cr.seller_id = %s ORDER BY cr.requested_date DESC LIMIT 5
    """, (session['user_id'],))
    records = cur.fetchall()

    # Fetch recent wallet history (Deposits & Cashouts)
    cur.execute("""
        SELECT transaction_type, amount, status, created_at 
        FROM wallet_transaction 
        WHERE user_id = %s 
        ORDER BY created_at DESC LIMIT 5
    """, (session['user_id'],))
    wallet_history = cur.fetchall()

    cur.close(); conn.close()
    
    return render_template('index.html', wallet=wallet, qr_token=qr['qr_code_token'] if qr else "PENDING", 
                           total_co2=co2_saved, records=records, prices=prices, wallet_history=wallet_history)

# --- 1. LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT * FROM "user" WHERE email = %s', (email,))
            user = cur.fetchone()
            cur.close(); conn.close()

            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session.update({'user_id': user['user_id'], 'role': user['role'], 'full_name': user['full_name'], 
                                'phone_number': user['phone_number'], 'postcode': user['postcode']})
                return redirect(url_for('index'))
            flash("Invalid email or password.", "danger")
        except Exception as e:
            flash(f"Database Error: {str(e)}", "danger")
    return render_template('login.html')

# --- 2. SIGNUP (With Friendly Error Mapping) ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        postcode = request.form.get('postcode')
        role = request.form.get('role')
        seller_type = request.form.get('seller_type')
        stall_name_input = request.form.get('stall_name')
        plate = request.form.get('plate_number')

        if not is_strong_password(password):
            flash("Password must be 8+ chars with Uppercase, Number, and Special Char.", "danger")
            return render_template('signup.html')
        
        if phone.startswith('0'): phone = '+60' + phone[1:]
        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            # 1. Insert into Master User Table
            cur.execute('INSERT INTO "user" (full_name, email, phone_number, password_hash, postcode, role) VALUES (%s,%s,%s,%s,%s,%s) RETURNING user_id', 
                        (name, email, phone, hashed_pw, postcode, role))
            uid = cur.fetchone()[0]

            if role == 'SELLER':
                final_name = name if seller_type == 'HOUSEHOLD' else stall_name_input
                token = f"QR_{email.split('@')[0].upper()}"
                cur.execute("INSERT INTO seller (user_id, stall_name, qr_code_token, seller_type) VALUES (%s,%s,%s,%s)", 
                            (uid, final_name, token, seller_type))
                cur.execute("INSERT INTO wallet (user_id) VALUES (%s)", (uid,))
                
            elif role == 'COLLECTOR':
                cur.execute("""
                    INSERT INTO collector (user_id, vehicle_plate, current_load_liters, max_capacity_liters, commission_balance) 
                    VALUES (%s, %s, 0, 200, 0)
                """, (uid, plate))

            conn.commit()
            flash("Account successfully created! Please log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            conn.rollback()
            error_msg = str(e).lower()
            if "user_email_key" in error_msg:
                flash("This email is already registered.", "warning")
            elif "user_phone_number_key" in error_msg:
                flash("This phone number is already in use.", "warning")
            else:
                flash(f"Signup failed: {str(e)}", "danger")
            return render_template('signup.html')
        finally:
            cur.close(); conn.close()
            
    return render_template('signup.html')

# --- 3. LOGOUT ---
@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

# --- 4. ADMIN ---
@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'ADMIN': return redirect(url_for('login'))
    now = datetime.datetime.now().strftime("%d %b %Y, %I:%M %p")
    return render_template('admin.html', now_time=now)

@app.route('/admin/pricing', methods=['GET', 'POST'])
def admin_pricing():
    if session.get('role') != 'ADMIN': return redirect(url_for('login'))
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    if request.method == 'POST':
        price_id = request.form['price_id']; new_rate = request.form['new_rate']
        cur.execute("UPDATE price_setting SET rate_per_liter = %s WHERE price_id = %s", (new_rate, price_id))
        conn.commit(); flash("Price structure updated.", "success")
    cur.execute("SELECT * FROM price_setting ORDER BY grade_name"); prices = cur.fetchall(); cur.close(); conn.close()
    return render_template('admin_pricing.html', prices=prices)

@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'ADMIN': return redirect(url_for('login'))
    search_query = request.args.get('search', '').strip()
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    query = """
        SELECT u.user_id, u.full_name, u.email, u.role, u.postcode, s.seller_type, s.stall_name, c.vehicle_plate
        FROM "user" u LEFT JOIN seller s ON u.user_id = s.user_id LEFT JOIN collector c ON u.user_id = c.user_id WHERE u.role != 'ADMIN'
    """
    params = []
    if search_query:
        query += " AND (u.full_name ILIKE %s OR u.email ILIKE %s OR s.stall_name ILIKE %s)"
        params = [f'%{search_query}%', f'%{search_query}%', f'%{search_query}%']
    cur.execute(query + " ORDER BY u.full_name ASC", params)
    all_users = cur.fetchall(); sellers = [u for u in all_users if u['role'] == 'SELLER']; collectors = [u for u in all_users if u['role'] == 'COLLECTOR']
    cur.close(); conn.close()
    return render_template('admin_users.html', sellers=sellers, collectors=collectors, search_val=search_query)

# --- 5. SELLER: NEW APPOINTMENT ---
@app.route('/request/new', methods=['GET', 'POST'])
def create_request():
    if session.get('role') != 'SELLER': return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Fetch user and schedule details
    cur.execute('SELECT u.*, sch.collection_day FROM "user" u LEFT JOIN collection_schedule sch ON u.postcode = sch.postcode WHERE u.user_id = %s', (session['user_id'],))
    user_info = cur.fetchone()
    
    cur.execute('SELECT area_name, postcode FROM collection_schedule ORDER BY area_name ASC')
    area_list = cur.fetchall()

    if request.method == 'POST':
        try:
            # Generate a fresh UUID string for the request_id primary key
            new_request_id = str(uuid.uuid4())
            
            # Match empty number inputs gracefully
            weight_input = request.form.get('weight')
            estimated_weight = float(weight_input) if weight_input and weight_input.strip() else None

            # SQL matching your exact database columns: request_id, seller_id, status, requested_date, etc.
            cur.execute("""
                INSERT INTO collection_request (
                    request_id, seller_id, status, requested_date, 
                    collection_address, preferred_time_slot, estimated_weight_kg, 
                    preferred_day_range, request_postcode
                )
                VALUES (%s, %s, 'Pending', NOW(), %s, %s, %s, %s, %s)
            """, (
                new_request_id,
                session['user_id'],
                request.form.get('address'),
                request.form.get('time_slot'),
                estimated_weight,
                request.form.get('day_range'),
                request.form.get('request_postcode')
            ))
            
            conn.commit()
            flash("Pickup successfully requested!", "success")
            
            # Redirects back to the same page to show the success message clearly without 404 errors
            return redirect(url_for('create_request'))
            
        except Exception as e:
            conn.rollback()
            flash(f"Error: {str(e)}", "danger")
            
    cur.close()
    conn.close()
    return render_template('request.html', user=user_info, areas=area_list)

@app.route('/request/cancel/<request_id>', methods=['POST'])
def cancel_collection_appointment(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db_conn = get_db_connection()
    cursor = db_conn.cursor()
    
    try:
        # Extra Security check: Ensure this pickup request actually belongs to the user logged in before deleting/modifying
        cursor.execute("""
            SELECT status FROM collection_request 
            WHERE request_id = %s::uuid AND user_id = %s::uuid
        """, (str(request_id), str(session['user_id'])))
        record = cursor.fetchone()
        
        if not record:
            flash("Appointment request item entity lookup failed.", "danger")
            return redirect(request_url_fallback())
            
        current_status = record[0]
        
        # Guard clause: Stop cancellation requests if a runner has already accepted the job
        if current_status != 'Pending':
            flash(f"Cannot cancel request. Job assignment status is already marked as: '{current_status}'.", "warning")
            return redirect(request_url_fallback())
            
        # Perform logical cancellation write update
        cursor.execute("""
            UPDATE collection_request 
            SET status = 'Cancelled' 
            WHERE request_id = %s::uuid
        """, (str(request_id),))
        
        db_conn.commit()
        flash("Your collection appointment has been successfully cancelled.", "success")
        
    except Exception as e:
        db_conn.rollback()
        print(f"CANCELLATION FAILURE TRANSACTION ERROR: {str(e)}")
        flash("An database infrastructure issue stopped that request alteration action.", "danger")
    finally:
        cursor.close()
        db_conn.close()
        
    return redirect(request_url_fallback())

def request_url_fallback():
    # Safely routes user right back to where they initiated the click action workflow
    return request.referrer or url_for('index')

# --- 6. COLLECTOR: ACCEPT A JOB ---
@app.route('/collector/accept_job/<uuid:request_id>', methods=['POST'])
def accept_job(request_id):
    if session.get('role') != 'COLLECTOR': return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE collection_request 
            SET collector_id = %s, status = 'Assigned' 
            WHERE request_id = %s AND status = 'Pending'
        """, (session['user_id'], str(request_id)))
        
        if cur.rowcount > 0:
            conn.commit()
            flash("Job accepted! It is now in your active pipeline.", "success")
        else:
            flash("Too late! This job was just accepted by another runner.", "warning")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {str(e)}", "danger")
    finally:
        cur.close(); conn.close()
    return redirect(url_for('tasks'))

# --- 7. LOGISTICS HUB (TASKS) ---
@app.route('/tasks')
def tasks():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
        
    search_query = request.args.get('search', '')
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        profile = None
        collector_postcode = None
        if session['role'] == 'COLLECTOR':
            cur.execute('SELECT u.postcode, u.phone_number, c.* FROM collector c JOIN "user" u ON c.user_id = u.user_id WHERE c.user_id = %s', (session['user_id'],))
            profile = cur.fetchone()
            if profile and profile['postcode']: 
                collector_postcode = profile['postcode'].split(',')[0].strip()

        query = """
            SELECT cr.*, 
                   COALESCE(s.stall_name, u.full_name) as stall_display_name, 
                   u.phone_number as seller_phone,
                   coll_u.full_name as runner_name,
                   coll_u.phone_number as runner_phone,
                   coll_p.vehicle_plate as runner_plate,
                   cd.liters as actual_liters
            FROM collection_request cr 
            JOIN "user" u ON cr.seller_id = u.user_id
            LEFT JOIN seller s ON u.user_id = s.user_id
            LEFT JOIN "user" coll_u ON cr.collector_id = coll_u.user_id
            LEFT JOIN collector coll_p ON cr.collector_id = coll_p.user_id
            LEFT JOIN collection_detail cd ON cr.request_id = cd.request_id
            WHERE (u.full_name ILIKE %s OR s.stall_name ILIKE %s)
        """
        params = [f'%{search_query}%', f'%{search_query}%']

        if session['role'] == 'SELLER':
            query += " AND cr.seller_id = %s"
            params.append(session['user_id'])
        elif session['role'] == 'COLLECTOR' and collector_postcode:
            query += " AND cr.request_postcode LIKE %s AND (cr.status IN ('Pending', 'Assigned', 'Collected', 'Verified')) AND (cr.collector_id IS NULL OR cr.collector_id = %s)"
            params.extend([f'{collector_postcode}%', session['user_id']])

        query += """ ORDER BY 
            CASE WHEN cr.status IN ('Pending', 'Assigned') THEN 1 ELSE 2 END,
            CASE WHEN preferred_day_range = 'Monday - Wednesday' THEN 1 WHEN preferred_day_range = 'Wednesday - Friday' THEN 2 WHEN preferred_day_range = 'Saturday - Sunday' THEN 3 ELSE 4 END,
            CASE WHEN preferred_time_slot = '9am - 12pm' THEN 1 WHEN preferred_time_slot = '12pm - 4pm' THEN 2 WHEN preferred_time_slot = '4pm - 9pm' THEN 3 ELSE 4 END """
        
        cur.execute(query, params)
        rows = cur.fetchall()
        
        # --- DYNAMIC WALLET BALANCE EXTRACTION ---
        wallet_balance = 0.00
        if session.get('role') == 'COLLECTOR':
            cur.execute("""
                SELECT COALESCE(balance, 0.00) AS balance 
                FROM public.wallet 
                WHERE user_id = %s
            """, [str(session['user_id'])])
            wallet_row = cur.fetchone()
            
            # Use tuple indexing [0] to bypass dictionary key errors safely, 
            # while keeping RealDictCursor happy
            if wallet_row:
                wallet_balance = float(list(wallet_row.values())[0])

    finally:
        cur.close()
        conn.close()
    
    for r in rows:
        if r['estimated_weight_kg']: 
            r['estimated_weight_kg'] = float(r['estimated_weight_kg'])
        if r['actual_liters']: 
            r['actual_liters'] = float(r['actual_liters'])

    current_load = 0.0
    total_earnings = 0.0
    
    if session['role'] == 'COLLECTOR':
        for r in rows:
            if r['status'] == 'Collected' and r['collector_id'] == session['user_id']:
                liters = float(r['actual_liters']) if r['actual_liters'] else 0.0
                current_load += liters
                total_earnings += 2.00 + (0.20 * liters)

        if current_load > 200.0:
            current_load = 200.0

    pending = [r for r in rows if r['status'] in ('Pending', 'Assigned')]
    completed = [r for r in rows if r['status'] in ('Collected', 'Verified')]
    completed.sort(key=lambda x: x['requested_date'], reverse=True)
    
    return render_template(
        'collector.html', 
        pending=pending, 
        completed=completed, 
        profile=profile, 
        search_val=search_query,
        current_load=round(current_load, 1),
        total_earnings=round(total_earnings, 2),
        wallet_balance=round(wallet_balance, 2) # Passed securely to the template
    )

# --- 8. VERIFICATION & SCANNERS ---
@app.route('/scan/<request_id>')
def scan_page(request_id):
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM price_setting ORDER BY grade_name"); prices = cur.fetchall(); cur.close(); conn.close()
    return render_template('scanner.html', request_id=request_id, prices=prices)

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    req_id = data.get('request_id'); scanned_token = data.get('qr_token')
    liters = float(data.get('liters')); grade_id = data.get('grade_id')

    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT s.qr_code_token FROM seller s JOIN collection_request cr ON s.user_id = cr.seller_id WHERE cr.request_id = %s", (req_id,))
    res = cur.fetchone()
    
    if res and res['qr_code_token'] == scanned_token:
        try:
            cur.execute("UPDATE collection_request SET status = 'Collected' WHERE request_id = %s", (req_id,))
            cur.execute("INSERT INTO collection_detail (request_id, price_id, liters) VALUES (%s, %s, %s)", (req_id, grade_id, liters))
            conn.commit(); return jsonify({"status": "success"})
        except Exception as e:
            conn.rollback(); return jsonify({"status": "fail", "message": str(e)})
    return jsonify({"status": "fail", "message": "Invalid QR Token"})

@app.route('/collector/verify_scan/<uuid:request_id>', methods=['POST'])
def verify_scan(request_id):
    if session.get('role') != 'COLLECTOR': 
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        actual_liters = request.form.get('actual_volume')
        oil_grade = request.form.get('oil_grade')
        scanned_token = request.form.get('qr_code_token')

        liters_val = float(actual_liters) if actual_liters else 0.0
        
        # Calculate earnings right here
        RATE_PER_LITER = 0.20
        BASE_FEE = 2.00
        total_earned = BASE_FEE + (RATE_PER_LITER * liters_val)

        # 1. Update Collection Request Status
        cur.execute("""
            UPDATE collection_request 
            SET status = 'Collected'
            WHERE request_id = %s AND status = 'Assigned'
        """, (str(request_id),))
        
        # 2. Insert Collection Detail
        cur.execute("""
            INSERT INTO collection_detail (request_id, liters, oil_grade, recorded_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (request_id) 
            DO UPDATE SET liters = EXCLUDED.liters, oil_grade = EXCLUDED.oil_grade
        """, (str(request_id), liters_val, oil_grade or 'Grade A'))

        # 3. Log the earnings directly into wallet_transaction (No new table needed!)
        cur.execute("""
            INSERT INTO wallet_transaction (user_id, amount, type, description, request_id, recorded_at)
            VALUES (%s, %s, 'EARNING', %s, %s, CURRENT_TIMESTAMP)
        """, (session['user_id'], total_earned, f"Collection payout for {liters_val}L", str(request_id)))

        # 4. Update Collector's Wallet Balance
        cur.execute("""
            UPDATE wallet 
            SET balance = balance + %s 
            WHERE user_id = %s
        """, (total_earned, session['user_id']))
        
        conn.commit()
        flash("Oil successfully collected and earnings credited!", "success")
        
    except Exception as e:
        conn.rollback()
        flash(f"Error processing scan update: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
        
    return redirect(url_for('tasks'))

## --- 9. UNLOAD DISBURSEMENT ROUTINE ---
@app.route('/collector/unload', methods=['POST'])
def unload_lorry():
    # 1. Secured check that safely boots unauthenticated users to login
    if 'user_id' not in session or session.get('role') != 'COLLECTOR':
        flash("Session expired or unauthorized access.", "danger")
        return redirect('/login')

    raw_collector_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor() 
    
    try:
        collector_str_id = str(raw_collector_id)

        # Target ONLY cargo items currently sitting inside this collector's truck hold
        cur.execute("""
            SELECT COALESCE(cd.liters, 0), cr.request_id, cr.status 
            FROM collection_request cr
            LEFT JOIN collection_detail cd ON cr.request_id = cd.request_id
            WHERE cr.status = 'Collected' AND cr.collector_id = %s
        """, [collector_str_id]) 
        active_cargo = cur.fetchall()

        if active_cargo:
            total_trip_earnings = 0.0
            
            # Calculate earnings for this specific trip based on actual logged liters
            for row in active_cargo:
                liters = float(row[0]) if row[0] else 0.0  
                total_trip_earnings += 2.00 + (0.20 * liters)

            # PRESENTATION GUARD: Ensure a wallet row actually exists for this user in DB
            cur.execute('SELECT wallet_id FROM public.wallet WHERE user_id = %s', [collector_str_id])
            wallet_exists = cur.fetchone()
            
            if not wallet_exists:
                target_wallet_id = str(uuid.uuid4())
                cur.execute("""
                    INSERT INTO public.wallet (wallet_id, user_id, balance, last_updated)
                    VALUES (%s, %s, 0.00, CURRENT_TIMESTAMP)
                """, (target_wallet_id, collector_str_id))
            else:
                target_wallet_id = wallet_exists[0]

            # Process database updates for the requests
            for row in active_cargo:
                req_id = row[1]
                old_status = row[2] 
                req_str_id = str(req_id)

                # Advance request status to 'Verified' so it moves out of active truck hold
                cur.execute("""
                    UPDATE collection_request 
                    SET status = 'Verified' 
                    WHERE request_id = %s
                """, [req_str_id])

                cur.execute("""
                    INSERT INTO status_history (history_id, request_id, old_status, new_status, changed_at)
                    VALUES (%s, %s, %s, 'Verified', CURRENT_TIMESTAMP)
                """, [str(uuid.uuid4()), req_str_id, old_status])

            # Force add the transit earnings permanently to the wallet table
            cur.execute("""
                UPDATE public.wallet 
                SET balance = balance + %s, last_updated = CURRENT_TIMESTAMP 
                WHERE user_id = %s
            """, (total_trip_earnings, collector_str_id))

            conn.commit()
            flash(f"Success! Cargo Unloaded. Added RM {total_trip_earnings:.2f} to your wallet.", "success")
        else:
            flash("Cargo load is empty. Nothing to unload!", "info")

    except Exception as e:
        conn.rollback()
        flash(f"Database Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()

    # Safely route back to the task list dashboard directly as a path string
    return redirect('/tasks') # Replace with 'index' or '/' if your function name differs

# --- 10. WALLET CASH OUT FORM & TRANSACTION HANDLER ---
@app.route('/wallet/withdraw', methods=['GET', 'POST'])
def withdraw():
    # 1. Protect Route: Ensure the user session is active
    if 'user_id' not in session:
        flash("Please log in to continue.", "danger")
        return redirect(url_for('login'))
        
    user_id = session['user_id']

    # 2. POST REQUEST HANDLER (When user submits the form)
    if request.method == 'POST':
        cursor = None
        db_conn = None
        try:
            bank_name = request.form.get('bank_name')
            account_number = request.form.get('account_number')
            amount_input = request.form.get('amount')

            if not bank_name or not account_number or not amount_input:
                flash("All fields are required.", "warning")
                return redirect(url_for('withdraw'))

            amount = float(amount_input)
            
            # Use your exact database connection helper
            db_conn = get_db_connection() 
            cursor = db_conn.cursor()
            
            # Fetch balance (Cast Python string to PostgreSQL uuid type explicitly)
            cursor.execute("SELECT balance FROM wallet WHERE user_id = %s::uuid", (str(user_id),))
            wallet_row = cursor.fetchone()

            if not wallet_row:
                flash("Wallet account records not found.", "danger")
                cursor.close()
                db_conn.close()
                return redirect(url_for('withdraw'))

            # Standard psycopg2 cursor returns a tuple, balance is at index 0
            current_balance = float(wallet_row[0])

            # Balance validation check
            if current_balance < amount:
                flash(f"Insufficient funds! Your live balance is RM {current_balance:.2f}.", "danger")
                cursor.close()
                db_conn.close()
                return redirect(url_for('withdraw'))

            # Deduct the withdrawal amount
            new_balance = current_balance - amount
            cursor.execute("UPDATE wallet SET balance = %s WHERE user_id = %s::uuid", (new_balance, str(user_id)))

            # Generate standardized random UUID hex values for primary keys
            new_withdrawal_id = str(uuid.uuid4())
            new_transaction_id = str(uuid.uuid4())

            # Insert transaction into withdrawal_request table matching your exact columns
            cursor.execute("""
                INSERT INTO withdrawal_request (withdrawal_id, user_id, amount, bank_name, account_number, status, created_at)
                VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, NOW())
            """, (new_withdrawal_id, str(user_id), amount, bank_name, account_number, 'Pending'))

            # Insert audit log transaction record into wallet_transaction table
            cursor.execute("""
                INSERT INTO wallet_transaction (transaction_id, user_id, amount, transaction_type, status, created_at)
                VALUES (%s::uuid, %s::uuid, %s, %s, %s, NOW())
            """, (new_transaction_id, str(user_id), amount, 'Withdrawal', 'Pending'))

            # Safely commit changes and shut connections down
            db_conn.commit()
            cursor.close()
            db_conn.close()

            flash(f"Cashout request of RM {amount:.2f} submitted successfully!", "success")
            return redirect(url_for('withdraw'))

        except Exception as e:
            if db_conn:
                db_conn.rollback()
                db_conn.close()
            if cursor:
                cursor.close()
            print("--- DATABASE EXCEPTION ERROR LOG ---")
            print(str(e))
            return f"Database Error during Payout: {str(e)}", 500

    # 3. GET REQUEST HANDLER (Initial page loading)
    db_conn = None
    cursor = None
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()
        cursor.execute("SELECT balance FROM wallet WHERE user_id = %s::uuid", (str(user_id),))
        wallet_data = cursor.fetchone()
        
        cursor.close()
        db_conn.close()

        if wallet_data:
            balance_val = wallet_data[0]
            wallet = {'balance': float(balance_val)}
        else:
            wallet = {'balance': 0.00}

        return render_template('withdraw.html', wallet=wallet)

    except Exception as e:
        if db_conn:
            db_conn.close()
        print("GET Request Crash:", str(e))
        return f"Internal Server Error: {str(e)}", 500

# --- 11. CHATBOT SYSTEM ---
@app.route('/chatbot', methods=['POST'])
def chatbot():
    msg = request.json.get('message', '').lower()
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT response_text FROM chatbot_kb WHERE %s LIKE '%%' || keyword || '%%' LIMIT 1", (msg,))
    res = cur.fetchone(); cur.close(); conn.close()
    return jsonify({"response": res['response_text'] if res else "I'm sorry, I don't have information on that. Ask about registration or wallet."})

# --- 12. MARKETING & EVENT TRACKING ---
@app.route('/events')
def events():
    conn = get_db_connection(); cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM collection_event WHERE event_date >= CURRENT_DATE ORDER BY event_date ASC")
    e_list = cur.fetchall(); cur.close(); conn.close()
    return render_template('events.html', events=e_list)

@app.route('/collector/toggle_duty', methods=['POST'])
def toggle_duty():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute('UPDATE collector SET is_on_duty = NOT is_on_duty WHERE user_id = %s', (session['user_id'],))
    conn.commit(); cur.close(); conn.close()
    return redirect(url_for('tasks'))

# --- 13. ADMIN: EVENT MANAGER (Add & Delete) ---
@app.route('/admin/events_manager', methods=['GET', 'POST'])
def admin_events():
    if session.get('role') != 'ADMIN': 
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        name = request.form['name']
        loc = request.form['location']
        post = request.form['postcode']
        date = request.form['date']
        
        file = request.files.get('image')
        filename = "event_default.jpg"
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        cur.execute("""
            INSERT INTO collection_event (event_name, location_name, postcode, event_date, image_filename)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, loc, post, date, filename))
        conn.commit()
        flash("New event published successfully!", "success")

    cur.execute("SELECT * FROM collection_event ORDER BY event_date DESC")
    events_list = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_events.html', events=events_list)

# --- ADMIN: DELETE USER ---
@app.route('/admin/delete_user/<string:user_id>')
def delete_user(user_id):
    if session.get('role') != 'ADMIN': 
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Delete from dependent tables first to avoid foreign key violation errors
        cur.execute('DELETE FROM public.seller WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM public.collector WHERE user_id = %s', (user_id,))
        
        # Finally delete from the main user table
        cur.execute('DELETE FROM public."user" WHERE user_id = %s', (user_id,))
        
        conn.commit()
        flash("User successfully deleted from the database.", "success")
    except Exception as e:
        conn.rollback()
        print(f"DELETE USER ERROR: {str(e)}")
        flash(f"Database Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
        
    return redirect(url_for('admin_users')) # Make sure this matches your admin users list function name

# --- ADMIN: DELETE EVENT ---
@app.route('/admin/delete_event/<uuid:id>')
def delete_event(id):
    if session.get('role') != 'ADMIN': 
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM collection_event WHERE event_id = %s', (str(id),))
        conn.commit()
        flash("Event successfully deleted from the Melaka database.", "success")
    except Exception as e:
        conn.rollback()
        print(f"DELETE ERROR: {str(e)}")
        flash(f"Database Error: {str(e)}", "danger")
    finally:
        cur.close()
        conn.close()
        
    return redirect(url_for('admin_events'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)