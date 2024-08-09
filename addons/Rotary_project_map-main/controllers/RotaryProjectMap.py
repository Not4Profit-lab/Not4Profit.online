from flectra import http, api, SUPERUSER_ID
#import logging

#_logger = logging.getLogger(__name__)

class RotaryProjectMapController(http.Controller):
    @http.route('/rotary_project_map', type='http', auth='public', website=True)
    def index(self, **kw):
        
        databaseCursor = http.request.cr
        environment = api.Environment(databaseCursor, SUPERUSER_ID,{})
        projectEnvironment = environment['project.project']
        partnerEnvironment = environment['res.partner']
        projects = projectEnvironment.sudo().search([('name', '!=', 'Internal')])       
        matching_projects_override = []
        matching_projects_has_club_information = []
        matching_projects_company_matches_existing_club_name = []
        company_name_to_matched_partner = {}

        # Build lists/dictionary from Projects
        for project in projects:
            #_logger.info("Processing project with id %s and name %s.", project.id, project.name)
            
            # UC 1 - Overridden Projects
            if project.project_latitude and project.project_longitude:
                #_logger.info("Project id %s is an overridden project.", project.id)
                matching_projects_override.append(project)

            # UC2 - Project's Company's Partner is a Rotary Club with Club Information (location data) populated.
            elif project.company_id.partner_id.club_name == project.company_id.partner_id.name:
                #_logger.info("Project id %s has club information in company's partner.", project.id)
                matching_projects_has_club_information.append(project)

            # UC3 - project's company's partner no location data (workaround for bad data)
            else:
                #_logger.info("Project id %s does not have club information in company's partner. Performing lookup.", project.id)
                
                # If not, then perform a lookup for Club's with the same name and Club Information (location data) populated.
                if project.company_id.name in company_name_to_matched_partner:
                    matched_partner = company_name_to_matched_partner[project.company_id.name]
                else:
                    matched_partners = partnerEnvironment.sudo().search([('club_name', '=', project.company_id.name)])

                    # Find the first Partner with location data
                    matched_partner = next((partner for partner in matched_partners if partner.club_latitude and partner.club_longitude), None)
                    company_name_to_matched_partner[project.company_id.name] = matched_partner

                if matched_partner:
                    #_logger.info("Matched partner found with id %s and name %s for project id %s.", matched_partner.id, matched_partner.name, project.id)
                    if matched_partner.club_latitude and matched_partner.club_longitude:
                        matching_projects_company_matches_existing_club_name.append(project)
                    else:
                        # Raise an error if the matched partner does not have location details
                        #_logger.info("Partner matched with name %s does not have location details.", matched_partner.name)
                        continue

        matching_projects_json_data = []

        # When constructing the JSON of the projects need to create in different way for each
        # UC 1 - Override
        for project in matching_projects_override:
            matching_projects_json_data.append({
                'name': project.name,
                'club_name': project.company_id.name,
                'club_latitude': project.project_latitude,
                'club_longitude': project.project_longitude
            })
        
        for project in matching_projects_has_club_information:
            #_logger.info("Processing project with id %s and name %s.", project.id, project.name)
            
            # Log the details of the associated company and partner
            company = project.company_id
            partner = company.partner_id
            #_logger.info("Company id is %s and name is %s.", company.id, company.name)
            #_logger.info("Partner id is %s, club name is %s, latitude is %s, and longitude is %s.", 
            #            partner.id, partner.club_name, partner.club_latitude, partner.club_longitude)
        
            matching_projects_json_data.append({
                'name': project.name,
                'club_name': project.company_id.partner_id.club_name,
                'club_latitude': project.company_id.partner_id.club_latitude,
                'club_longitude': project.company_id.partner_id.club_longitude
            })

        for project in matching_projects_company_matches_existing_club_name:
            matched_partner = company_name_to_matched_partner[project.company_id.name]
            if matched_partner:
                matching_projects_json_data.append({
                    'name': project.name,
                    'club_name': matched_partner.club_name,
                    'club_latitude': matched_partner.club_latitude,
                    'club_longitude': matched_partner.club_longitude
                })
            else:
                #_logger.info("No matching partner with location details found for project %s.", project.name)
                continue

        return http.request.render('rotary_project_map.rotary_project_map', {'partners_data': matching_projects_json_data})