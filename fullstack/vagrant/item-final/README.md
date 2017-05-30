Description:
    - Mountain bike trail networks reviews in the western USA.
    - Login with Google+ to create and edit new regions and trail networks.

Open the app:
    - Install Vagrant and VirtualBox on your machine
    - Cd to the vagrant file in the project directory and type 'vagrant up'
    - Login to the vagrant machine with 'vagrant ssh'
    - Cd into the item-final directory with 'cd /vagrant' 'cd item-final'
    - Launch the server with 'python projectfinal.py'
    - Navigate to localhost:5000 in your web browser
    - If there are not any regions or trails on the web page, 'ctrl-c' to
      stop the server and 'python lotsoftrailswithusers.py' to populate the database.

JSON Endpoints:
    - JSON endpoints for all regions, localhost:5000/mtbtrails/JSON
    - JSON endpoints for a region's trail network, localhost:5000/mtbtrails/int:region_id/trail/JSON
    - JSON endpoints for individual trails, localhost:5000/mtbtrails/int:region_id/trail/JSON