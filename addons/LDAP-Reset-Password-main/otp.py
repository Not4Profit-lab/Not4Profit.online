from flectra import models, fields

class Otp(models.Model):
    _name = 'otp'
    _description = 'One-Time Password'
    
    user_id = fields.Many2one('res.users', string='User')
    otp_code = fields.Char(string='OTP Code', required=True)
    expiration_time = fields.Datetime(string='Expiration Time')