from flectra import models, fields

class ProjectProject(models.Model):
    _inherit = 'project.project'

    project_latitude = fields.Float(string='Latitude (Override)', 
                                    help='This latitude value will be used instead of the company\'s partner latitude value.')
    
    project_longitude = fields.Float(string='Longitude (Override)', 
                                     help='This longitude value will be used instead of the company\'s partner longitude value.')
    