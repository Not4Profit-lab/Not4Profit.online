var map;
var markers = []; // Global variable to store all markers

function initMap() {
    map = new google.maps.Map(document.getElementById('map'), {
        center: {lat: -25.2744, lng: 133.7751},
        zoom: 4
    });
    var partners = partnersData;
    if (!partnersData || partnersData.length === 0) {
        console.error('No partners data available.');
    }
    else {
        partners.forEach(location => {
            let marker = new google.maps.Marker({
                position: {lat: parseFloat(location['club_latitude']), lng: parseFloat(location['club_longitude'])},
                map,
                title: location['name'],
                club_name: location['club_name'], // Add custom property
                project_name: location['name']    // Add custom property
            });
            
            markers.push(marker); // Add the marker to the global array
    
            let content = '<h3 style="font-size: 18px; margin: 10px 0;">' + location['name'] + '</h3>' +
                        '<div style="font-size: 14px; color: #666;">' + location['club_name'] + '</div>';
    
            let infowindow = new google.maps.InfoWindow({
                content: content
            });
    
            marker.addListener('click', function() {
                infowindow.open(map, marker);
            });
            
            // Remove the highlighting effect
            google.maps.event.addListener(infowindow, 'domready', function() {
                jQuery(".gm-ui-hover-effect").css({
                    "border": "none",
                    "outline": "none"
                });
            });
        });
    }

    // Attach a listener to the search box
    document.getElementById('search-box').addEventListener('keyup', filterMarkers);
}

// Function to filter the markers
function filterMarkers() {
    var searchTerm = document.getElementById('search-box').value.toLowerCase();

    // Iterate through the markers and hide/show them based on the search term
    markers.forEach(marker => {
        var projectName = marker.project_name.toLowerCase();
        var clubName = marker.club_name.toLowerCase();

        if (projectName.includes(searchTerm) || clubName.includes(searchTerm)) {
            marker.setMap(map); // Show the marker
        } else {
            marker.setMap(null); // Hide the marker
        }
    });
}