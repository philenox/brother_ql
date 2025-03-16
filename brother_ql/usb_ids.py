"""
USB product ID to printer model mapping
"""

USB_MODELS = {
    0x2015: 'QL-700',  # Example mapping
    0x20c0: 'QL-600',  # Adding QL-600 mapping
}

def get_model(product_id):
    """Get printer model from USB product ID"""
    return USB_MODELS.get(product_id) 