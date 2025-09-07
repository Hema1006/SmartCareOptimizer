# app.py

import os  # Import the os module
from dotenv import load_dotenv  # Import dotenv
import pandas as pd
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from sqlalchemy import create_engine
from reportlab.graphics.shapes import Rect, Drawing, Circle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import inch
from models import db, User, UserOTP, PasswordResetToken, Appointment
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta

# PDF imports
from reportlab.lib.pagesizes import LETTER
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# JWT Security Imports
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# --- Import your ML logic ---
from ml_pipeline import get_top_providers_for_member, calculate_payments_row, calculate_quality_score

# --- Load Environment Variables ---
# This line loads the variables from your .env file
load_dotenv()

# --- App Initialization and Configuration ---
app = Flask(__name__, template_folder='templates')
CORS(app)

# --- MODIFIED: Load configuration from environment variables ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ("Smart Care Optimizer", os.getenv('MAIL_USERNAME'))

# Snowflake Connection Settings from Environment Variables
SNOWFLAKE_USER = os.getenv('SNOWFLAKE_USER')
SNOWFLAKE_PASSWORD = os.getenv('SNOWFLAKE_PASSWORD')
SNOWFLAKE_ACCOUNT = os.getenv('SNOWFLAKE_ACCOUNT')
SNOWFLAKE_DATABASE = os.getenv('SNOWFLAKE_DATABASE')
SNOWFLAKE_SCHEMA = os.getenv('SNOWFLAKE_SCHEMA')
SNOWFLAKE_WAREHOUSE = os.getenv('SNOWFLAKE_WAREHOUSE')

# --- Initialize Extensions ---
db.init_app(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'home'
jwt = JWTManager(app)


from math import radians, sin, cos, sqrt, atan2 # <-- ADD THIS IMPORT

# --- ADD THIS HELPER FUNCTION ---
def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculates the distance between two points in miles."""
    R = 3958.8  # Radius of Earth in miles
    lat1_rad, lon1_rad = radians(lat1), radians(lon1)
    lat2_rad, lon2_rad = radians(lat2), radians(lon2)
    
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    
    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    
    return R * c

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- MODIFIED: Load Data Globally from Snowflake ---
try:
    # Create the SQLAlchemy engine for Snowflake using variables
    snowflake_engine = create_engine(
        f"snowflake://{SNOWFLAKE_USER}:{SNOWFLAKE_PASSWORD}@{SNOWFLAKE_ACCOUNT}/"
        f"{SNOWFLAKE_DATABASE}/{SNOWFLAKE_SCHEMA}?warehouse={SNOWFLAKE_WAREHOUSE}"
    )

    # Load data from Snowflake tables into pandas DataFrames
    print("Connecting to Snowflake to load data...")
    members_df = pd.read_sql("SELECT * FROM MEMBERS", snowflake_engine)
    providers_df = pd.read_sql("SELECT * FROM PROVIDER", snowflake_engine)

    # CRITICAL: Convert column names to lowercase
    members_df.columns = [col.lower() for col in members_df.columns]
    providers_df.columns = [col.lower() for col in providers_df.columns]

    print("✅ Successfully loaded members and providers data from Snowflake.")
    if not os.path.exists('reports'):
        os.makedirs('reports')

except Exception as e:
    print(f"❌ Error loading data from Snowflake: {e}.")
    print("Application will run with empty dataframes. API calls for providers will fail.")
    members_df = pd.DataFrame()
    providers_df = pd.DataFrame()


# --- All other functions (PDF generation, routes, etc.) remain unchanged ---

def create_premium_styles():
    # ... (rest of your code is unchanged)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='HeroTitle', fontSize=34, leading=40,
        textColor=colors.white, alignment=TA_CENTER,
        spaceAfter=8, fontName='Helvetica-Bold'
    ))
    styles.add(ParagraphStyle(
        name='HeroSubtitle', fontSize=15, leading=20,
        textColor=colors.HexColor("#B3E5FC"),
        alignment=TA_CENTER, spaceAfter=30
    ))
    styles.add(ParagraphStyle(
        name='CardHeader', fontSize=18, leading=22,
        textColor=colors.HexColor("#0277BD"),
        alignment=TA_LEFT, spaceAfter=15,
        fontName='Helvetica-Bold'
    ))
    styles.add(ParagraphStyle(
        name='CustomBullet', fontSize=12, leading=16,
        leftIndent=20, bulletIndent=10, spaceAfter=5
    ))
    return styles
premium_styles = create_premium_styles()


def create_hero_header():
    # ... (rest of your code is unchanged)
    drawing = Drawing(500, 160)
    drawing.add(Rect(0, 0, 500, 160, fillColor=colors.HexColor("#0D47A1"), strokeColor=None))
    drawing.add(Rect(0, 120, 500, 40, fillColor=colors.HexColor("#1565C0"), strokeColor=None))
    drawing.add(Rect(0, 140, 500, 20, fillColor=colors.HexColor("#1976D2"), strokeColor=None))
    drawing.add(Rect(50, 120, 20, 5, fillColor=colors.white, strokeColor=None))
    drawing.add(Rect(57, 113, 6, 19, fillColor=colors.white, strokeColor=None))
    for x in [420, 440, 460]:
        drawing.add(Circle(x, 130, 6, fillColor=colors.HexColor("#42A5F5"), strokeColor=None))
    return drawing


def generate_provider_report(member, providers, filename="provider_report.pdf"):
    # ... (rest of your code is unchanged)
    doc = SimpleDocTemplate(filename, pagesize=LETTER,
                            leftMargin=30, rightMargin=30,
                            topMargin=20, bottomMargin=40)
    story = []

    story.append(create_hero_header())
    story.append(Spacer(1, -140))
    story.append(Paragraph("SmartCare", premium_styles['HeroTitle']))
    story.append(Paragraph("OPTIMIZER", premium_styles['HeroTitle']))
    story.append(Paragraph("Advanced Healthcare Analytics & Cost Optimization", premium_styles['HeroSubtitle']))
    story.append(Spacer(1, 30))

    story.append(Paragraph("👤 MEMBER INFORMATION", premium_styles['CardHeader']))
    member_data = [
        ["Member ID:", member.get("member_id", "N/A")],
        ["Age:", member.get("age", "N/A")],
        ["Gender:", member.get("gender", "N/A")],
        ["Primary Specialty Needed:", member.get("primary_specialty_needed", "N/A")],
        ["Secondary Specialty Needed:", member.get("secondary_specialty_needed", "N/A")],
        ["Coverage Plan:", member.get("coverage_plan", "N/A")]
    ]
    member_table = Table(member_data, colWidths=[2 * inch, 3.5 * inch])
    member_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor("#0277BD")),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E3F2FD")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(member_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("📊 KEY PERFORMANCE METRICS", premium_styles['CardHeader']))
    total_member_cost = providers["member_share"].sum()
    total_insurer_cost = providers["insurance_payment"].sum()
    avg_coverage = 100 * (total_insurer_cost / (total_insurer_cost + total_member_cost)) if (
                                                                                                    total_insurer_cost + total_member_cost) > 0 else 0
    metrics_data = [
        [f"{len(providers)} Providers\nAvailable", f"${total_member_cost:,.2f}\nMember Cost",
         f"${total_insurer_cost:,.2f}\nInsurer Coverage", f"{avg_coverage:.1f}%\nAvg Coverage"]
    ]
    metrics_table = Table(metrics_data, colWidths=[1.8 * inch] * 4, rowHeights=[0.8 * inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('BOX', (0, 0), (-1, -1), 2, colors.HexColor("#E3F2FD")),
        ('INNERGRID', (0, 0), (-1, -1), 1, colors.HexColor("#E3F2FD")),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#0277BD")),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER')
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("🏥 PROVIDER INFORMATION", premium_styles['CardHeader']))
    for _, row in providers.iterrows():
        provider_data = [
            ["Provider Name:", row.get("name", "N/A")],
            ["Primary Specialty:", row.get("specialty", "N/A")],
            ["Secondary Specialty:", row.get("secondary_specialty", "N/A")],
            ["Distance:", f"{row.get('distance_miles', 0):.2f} miles"],
            ["Quality Score:", row.get("quality_score", "N/A")],
            ["Insurer Pays:", f"${row.get('insurance_payment', 0):,.2f}"],
            ["Member Pays:", f"${row.get('member_share', 0):,.2f}"]
        ]
        provider_table = Table(provider_data, colWidths=[1.7 * inch, 3.8 * inch])
        provider_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor("#0277BD")),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E3F2FD")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(provider_table)
        story.append(Spacer(1, 12))

    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0277BD")))
    footer_content = "<b>SmartCare Optimizer</b> | www.smartcare-optimizer.com | 📧 analytics@smartcare.com"
    footer_style = ParagraphStyle('Footer', fontSize=9, alignment=TA_CENTER, textColor=colors.HexColor("#0277BD"))
    story.append(Paragraph(footer_content, footer_style))

    doc.build(story)
    return filename


# --- Your API Routes Here, completely unchanged ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    #...
    data = request.get_json()
    email = data.get('email')
    username = data.get('name')
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered.'}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already taken.'}), 409
    otp = UserOTP.generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    new_otp = UserOTP(email=email, otp=otp, expires_at=expires_at)
    db.session.add(new_otp)
    db.session.commit()
    try:
        subject = "Your Verification Code"
        html_body = render_template('otp_email.html', subject=subject, title="Email Verification", username=username,
                                    body_text="We received a request to verify your email address. Please use the verification code below to complete your account setup.",
                                    otp=otp, year=datetime.utcnow().year)
        msg = Message(subject, recipients=[email], html=html_body)
        mail.send(msg)
        return jsonify({'success': True, 'message': 'OTP sent to your email.'})
    except Exception as e:
        print(f"Mail sending error: {e}")
        return jsonify({'success': False, 'message': 'Could not send OTP email.'}), 500


@app.route('/api/auth/verify-and-register', methods=['POST'])
def verify_and_register():
    #...
    data = request.get_json()
    email = data.get('email')
    otp_code = data.get('otp')
    username = data.get('name')
    password = data.get('password')
    otp_entry = UserOTP.query.filter_by(email=email, otp=otp_code, is_verified=False).order_by(
        UserOTP.id.desc()).first()
    if not otp_entry or not otp_entry.is_valid():
        return jsonify({'success': False, 'message': 'Invalid or expired OTP.'}), 400
    otp_entry.is_verified = True
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    access_token = create_access_token(identity=new_user.email)
    return jsonify({'success': True, 'message': 'Registration successful!', 'access_token': access_token,
                    'user': {'username': new_user.username, 'email': new_user.email}})

# ... etc. all your other routes remain exactly the same
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        access_token = create_access_token(identity=user.email)
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'access_token': access_token,
            'user': {'username': user.username, 'email': user.email}
        })
    return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401



@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully.'})


@app.route('/api/auth/check-auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({'isLoggedIn': True, 'user': {'username': current_user.username, 'email': current_user.email}})
    return jsonify({'isLoggedIn': False})


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        otp = UserOTP.generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        new_otp = UserOTP(email=email, otp=otp, expires_at=expires_at)
        db.session.add(new_otp)
        db.session.commit()
        try:
            subject = "Your Password Reset Code"
            html_body = render_template('otp_email.html', subject=subject, title="Password Reset",
                                        username=user.username,
                                        body_text="We received a request to reset your password. Use the verification code below. If you did not request this, you can safely ignore this email.",
                                        otp=otp, year=datetime.utcnow().year)
            msg = Message(subject, recipients=[email], html=html_body)
            mail.send(msg)
        except Exception as e:
            print(f"Mail sending error: {e}")
    return jsonify(
        {'success': True, 'message': 'If an account with that email exists, a password reset OTP has been sent.'})


@app.route('/api/auth/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json()
    email = data.get('email')
    otp_code = data.get('otp')
    otp_entry = UserOTP.query.filter_by(email=email, otp=otp_code, is_verified=False).order_by(
        UserOTP.id.desc()).first()
    if not otp_entry or not otp_entry.is_valid():
        return jsonify({'success': False, 'message': 'Invalid or expired OTP.'}), 400
    otp_entry.is_verified = True
    db.session.commit()
    return jsonify({'success': True, 'message': 'OTP verified successfully.'})


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp_code = data.get('otp')
    new_password = data.get('password')
    verified_otp = UserOTP.query.filter_by(email=email, otp=otp_code, is_verified=True).order_by(
        UserOTP.id.desc()).first()
    if not verified_otp or verified_otp.expires_at < datetime.utcnow():
        return jsonify(
            {'success': False,
             'message': 'Invalid or expired request. Please try the forgot password process again.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    user.set_password(new_password)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Password has been reset successfully.'})


@app.route('/')
def home():
    return render_template('Home.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('InputPage.html')


@app.route('/map')
@login_required
def map_view():
    return render_template('Map.html')


@app.route('/api/get-all-providers')
@jwt_required()
def get_all_providers():
    if providers_df.empty:
        return jsonify({"error": "Provider data not available"}), 500
    df = providers_df.copy()
    if 'name' not in df.columns and 'provider_name' in df.columns:
        df.rename(columns={'provider_name': 'name'}, inplace=True)
    return jsonify(df.to_dict(orient='records'))


@app.route('/api/generate-report', methods=['POST'])
@jwt_required()
def generate_report_api():
    data = request.get_json()
    member_id = data.get('member_id')
    provider_id = data.get('provider_id')

    if not member_id or not provider_id:
        return jsonify({'message': 'Both Member ID and Provider ID are required.'}), 400

    member_data = members_df[members_df["member_id"] == member_id]
    if member_data.empty:
        return jsonify({'message': f'Member ID {member_id} not found.'}), 404
    member = member_data.iloc[0].to_dict()

    provider_series = providers_df[providers_df['provider_id'] == provider_id]
    if provider_series.empty:
        return jsonify({'message': f'Provider ID {provider_id} not found.'}), 404

    provider_df = provider_series.copy()
     # --- ADD THIS BLOCK TO CALCULATE DISTANCE ---
    provider_lat = provider_df.iloc[0]['latitude']
    provider_lon = provider_df.iloc[0]['longitude']
    distance = haversine_distance(member['latitude'], member['longitude'], provider_lat, provider_lon)
    provider_df['distance_miles'] = distance
    # --- END OF BLOCK ---

    payments = provider_df.apply(lambda r: calculate_payments_row(r, member), axis=1)
    provider_df.loc[:, "insurance_payment"] = [p[0] for p in payments]
    provider_df.loc[:, "member_share"] = [p[1] for p in payments]
    if "quality_score" not in provider_df.columns:
        provider_df["quality_score"] = provider_df.apply(calculate_quality_score, axis=1).round(1)

    filename = f"reports/provider_report_{member_id}_{provider_id}.pdf"
    generate_provider_report(member, provider_df, filename=filename)
    return send_file(filename, as_attachment=True, mimetype='application/pdf')


@app.route('/api/find-providers', methods=['POST'])
@jwt_required()
def find_providers_api():
    data = request.get_json()
    member_id = data.get('member_id')
    if not member_id:
        return jsonify({'message': 'Member ID is required.'}), 400
    if members_df.empty or providers_df.empty:
        return jsonify({'message': 'Server data not available.'}), 500
    member_data = members_df[members_df["member_id"] == member_id]
    if member_data.empty:
        return jsonify({'message': f'Member ID {member_id} not found.'}), 404
    member = member_data.iloc[0].to_dict()
    
    recommended = get_top_providers_for_member(member, providers_df, top_n=3)
    
    response_data = {
        "providers": recommended.to_dict(orient='records'),
        "member_location": {"lat": member['latitude'], "lon": member['longitude']}
    }
    return jsonify(response_data)


@app.route('/api/book-appointment', methods=['POST'])
@jwt_required()
def book_appointment():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 401

    data = request.get_json()
    try:
        required_fields = ['provider_id', 'provider_name', 'patient_name', 'contact_no', 'appointment_date',
                           'appointment_time']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'message': 'Missing required appointment data.'}), 400

        appt_date = datetime.strptime(data['appointment_date'], '%Y-%m-%d').date()
        appt_time = datetime.strptime(data['appointment_time'], '%H:%M').time()

        existing_appointment = Appointment.query.filter_by(
            provider_id=data['provider_id'],
            appointment_date=appt_date,
            appointment_time=appt_time
        ).first()

        if existing_appointment:
            return jsonify({'success': False,
                            'message': 'This provider is already booked for the selected date and time. Please choose another slot.'}), 409

        new_appointment = Appointment(
            user_id=user.id,
            provider_id=data['provider_id'],
            provider_name=data['provider_name'],
            patient_name=data['patient_name'],
            contact_no=data['contact_no'],
            appointment_date=appt_date,
            appointment_time=appt_time
        )
        db.session.add(new_appointment)
        db.session.commit()

        try:
            source_page = data.get('source')
            send_with_report = (source_page != 'map_page')

            provider_series = providers_df.loc[providers_df['provider_id'] == data['provider_id']]
            provider_address = "Address not available"
            if not provider_series.empty:
                provider_address = provider_series.iloc[0]['address']

            html_body = render_template('appointment_confirmation_email.html',
                                        username=user.username, appointment=new_appointment,
                                        provider_address=provider_address, with_report=send_with_report,
                                        year=datetime.utcnow().year)

            msg = Message("Your Appointment Confirmation | Smart Care Optimizer", recipients=[user.email],
                          html=html_body)

            if send_with_report:
                member_id_for_report = data.get('member_id')
                member_data_for_report = members_df[members_df['member_id'] == member_id_for_report] if member_id_for_report else pd.DataFrame()

                # --- MODIFICATION START ---
                if not member_data_for_report.empty:
                    member_for_pdf = member_data_for_report.iloc[0].to_dict()
                else:
                    # Create a more complete default dictionary to prevent "N/A" in the PDF
                    member_for_pdf = {
                        "member_id": f"User Account: {user.username}",
                        "age": "Not Provided",
                        "gender": "Not Provided",
                        "primary_specialty_needed": "Not Specified",
                        "secondary_specialty_needed": "Not Specified",
                        "coverage_plan": "Default Plan"
                    }
                # --- MODIFICATION END ---

                provider_df_single = provider_series.copy()

                # --- ADD THIS BLOCK TO CALCULATE DISTANCE ---
                provider_lat = provider_df_single.iloc[0]['latitude']
                provider_lon = provider_df_single.iloc[0]['longitude']
                distance = haversine_distance(member_for_pdf['latitude'], member_for_pdf['longitude'], provider_lat, provider_lon)
                provider_df_single['distance_miles'] = distance
                
                payments = provider_df_single.apply(lambda r: calculate_payments_row(r, member_for_pdf), axis=1)
                provider_df_single.loc[:, "insurance_payment"] = [p[0] for p in payments]
                provider_df_single.loc[:, "member_share"] = [p[1] for p in payments]

                report_filename = f"reports/appointment_report_{new_appointment.id}.pdf"
                generate_provider_report(member_for_pdf, provider_df_single, filename=report_filename)

                with app.open_resource(report_filename) as fp:
                    msg.attach(f"{new_appointment.provider_name}_Report.pdf", "application/pdf", fp.read())
                os.remove(report_filename)

            mail.send(msg)

        except Exception as e:
            print(f"Error sending confirmation email for appointment {new_appointment.id}: {e}")

        return jsonify({'success': True, 'message': 'Appointment booked successfully!'})
    except Exception as e:
        db.session.rollback()
        print(f"Error booking appointment: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while booking the appointment.'}), 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(
        host='0.0.0.0',
        port=443,
        debug=True,
        ssl_context=('/etc/ssl/certs/selfsigned.crt', '/etc/ssl/private/selfsigned.key')
    )
