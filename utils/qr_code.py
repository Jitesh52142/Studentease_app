import qrcode
from io import BytesIO
import base64

def generate_payment_qr(amount, product_id, description):
    """
    Generate a QR code for payment with the given details.
    Returns the QR code as a base64 encoded string.
    """
    # Create payment data (you can customize this based on your needs)
    payment_data = f"amount={amount}&product_id={product_id}&description={description}"
    
    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # Add data
    qr.add_data(payment_data)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}" 