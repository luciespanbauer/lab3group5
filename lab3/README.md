# ISSEM Lab - Infant Incubator Model and Simulator

The Infant Incubator is designed to provide a safe, controlled space for infants to live while their vital organs develop. Unlike a simple bassinet, an incubator provides an environment that can be adjusted to provide the ideal temperature as well as the perfect amount of oxygen, humidity, and light.

## Task:

Please carefully read and understand about the Infant incubator and answer the following two questions:

1. Find the SQL injection of the login page. You need to submit a screenshot of the screen after having logged in using the payload you find.
2. Retrieve the plaintext password from the database and submit the same.

# Steps to run the application on local

1. Open the terminal, make sure you are in the root directory
2. Run the following command to install all the requirements whilst in the root directory: pip3 install -r requirements.txt
3. Run the SampleNetworkServer.py file using the following command: python3 SampleNetworkServer.py
4. You will be able to see the incubator working now
5. Now we need to run the flask application
6. Open a new terminal window
7. Type the following commands in succession:
- Ensure you are in the root directory
- export FLASK_APP="app.py"
- flask run
- If you run into any errors you update your python

8. The application will start running on the localhost and you will be able to open the same in browser using the link mentioned in the console
9. Run that link in the browser where you will see the flask application running.

Incase the above steps are not working you can communicate with the TA's to help you out.

## Submission

This is a group submission. Please write your responses in a PDF and include it in the writeup/ directory. Also include the PDF as a separate file at upload time in Brightspace. The title of the file should be `lab{3 or 4}_group_<group_number>.pdf`. Good luck!

## Infant Incubator Model Explained

Cybersecurity education lacks practicality. We know the security principles. We know the importance of cryptography and building-security-in. We know the importance of an adversarial mindset (the security mindset). We know the importance of exposing assumptions (especially implicit ones). However, how many of us know how to apply these theoretical principles in the real world? How to trade off security for the other abilities. While build in security is incomplete, we also need to plan for upgrades.

To appreciate cybersecurity in practice, we must attempt to build a product with cybersecurity in mind. This Infant Incubator is such a product. It will be used as part of the Practical Cybersecurity series of courses that we are developing.

The infant incubator was chosen because:

1. It is a simple, yet valuable product.
2. It is a cyber-physical system that exists in the real world, but can have a virtual (networked) presence.
3. It is a medical device, which means there are laws and regulations that must be accounted for.
4. Safety is paramount, not security. There are no arguments.
5. It can operate as a standalone device, but the allure of being able to control and monitor over the network is there.

## Simple Model

This Infant Incubator Simulator is based on a very simple heat transfer model with three things (or bodies).

First is the room in which the incubator will sit. We assume that the ROOM is large enough and well controlled so that the temperature never changes over time.

Second is the incubator itself which is modeled as a rectangular prism (box). It has three dimensions, width (w), depth (d) and height (h) all measured in meters. Also this particular incubator is made out of plexi-glass acrylic although other materials can be used as discussed later.

The last body is the infant which is modeled as a body as described in further detail below.

                          ROOM
          ,-----------------------------------.
          |/////   Plexiglass Acrylic   //////|
          |/,-------------------------------./|
          |/|                               |/|
          |/|          CHAMBER (HS)         |/|
        R |/|     ,-------------------.     |/|  R
        O |/|     |****   SKIN   *****|     |/|  O
        O |/|     |*,---------------.*|     |/|  O
        M |/|     |*|               |*|     |/|  M
          |/|     |*|  INFANT (HS)  |*|     |/|
          |/|_____|*|_______________|*|_____|/|

                        INSULATOR

As shown, this is a closed system where 5 of the 6 faces of the incubator are exposed to the room; the bottom face is not. Imagine the incubator being placed on an insulating pad where heat loss is negligible.

Since the infant is normally placed in the middle of the incubator bed, we assume that there is no direct contact between skin and the chamber walls. As a result, all energy transfers are either between the Incubator Chamber and the Room through the Plexiglass or, in the case when an infant is inside, between the Infant and the Incubator through skin.

## Energy/Heat Transfer Calculations

The law of thermodynamics that energy must be conserved. Any energy lost (or gained) by the Chamber must be gained (or lost) by the Infant or the Room. To simplify things further, we will also assume that energy is always uniformly distributed within each body which means that the temperature is also uniform. With this assumption, we can always calculate the current temperature of a thing given its energy content or the energy content given its temperature as long as we know its specific heat.

Specific heat is not constant. It changes with temperature and pressure, but we will not account for this in this model. For simplicity, we use the following values.

- The specific heat for Air at sea level (1 ATM) is 1.012 J / g / degK = 1012 J / kg / degK
- The specific heat for Animal Tissue is about 3.5 J / g / degK. = 3500 J / kg / degK

To calculate the mass of air (in Chamber ) or the Infant we also need to know the density and volume. However, while volume makes sense for the chamber -- width (or lenght), depth, height -- Infants are normally measured with their weight and length. We know that weight depends on gravity, which in turn varies by location, but will also conveniently ignore that and assume that weight and mass are equal. As mentioned above, we will also ignore the size of the room by assuming that the temperature in the room is always constant (meaning there is some external heat source or sink that ensures this).

Once again the densities can change given environmental and other conditions, but we will use the following constants.

- The density of a human body is about the same as that of water = 1000 kg/m^3.
- The density of air at room temperature (20 degC and 101.325 kPa) = 1.2041 kg/m^3)

Given the constants above and initial state information, the total energy that is latent in the two systems (Chamber and Infant) can be calculated.

### Heat Transfer

Heat transfer does not take place instantaneously but at a specifed rate. The rate at which heat (energy) is transferred varies depending on environmental conditions but also on how the transfer occurs (conduction, convection or radiation.) For convenience reasons, we will assume that heat transfer can be modeled using a single constant U (known as the U-factor). We use the following values:

- Heat transfer through human skin occurs at a rate of 5.5 W / m^2 / degK ([2]) = 5.5 J / S / m^2 / degK
- Heat transfer through plexiglass at a rate of .90 BTU/hr/SqFt/degF = 5.11 J / S / m^2 / degK

Since the degK is the degrees of temperature difference between the two sides of the material, this means that we need to know what the temperature of the Infant, Chamber and Room are in order to use calcuate the amount of energy transfer. Then after the energy has been transfered over a specific period of time, we will need to update the temperature accordingly for the next iteration of the simulation.

The reliance on temperature differential is convenient since we think of Infants and chambers having a temperature of X rather than an energy of X.

In addition to the temperature differential, the heat transfer constants also depend on the exposed surface area. The surface area for the Chamber is wd (for top) + 2wh (front and back) + 2dh (sides). The surface area of a human body is more complicated, although there is a number of formulas that approximate surface area. One of them is the Mosteller formula which is SQRT(mass _ length / 3600). In this case, mass is in kg but length is in cm which means surface area of a human body is SQRT(100 _ m \* l / 3600) where the resulting unit is m^2, kg for mass and m for height. We do not account for the fact that most parts of the infant will not be exposed to air.

## Simulation

Putting everything together, the simulation will take place in a sequence of coordinated steps.

During each timestep (simulation iteration) we will:

1. Calculate temperature differentials T_RC and T_CI for the difference in temperatures between the Room and Chamber and Chamber and Infant respectively.
2. Calculate E_I, the energy gained by the Infant's internal heater, i.e. energy gained due to metabolism over the past timestep.
3. Calculate E_IC, the energy gained (or lost if negative) by the Infant, using T_CI and the constants above. This is the same amount of energy that will be lost (or gained) by the Chamber due to the Infant.
4. Calculate E_C, the energy gained by the Chamber's heater.
5. Calculate E_CR, the energy gained (or lost if negative) by the Chamber to the Room using T_RC and the constants above.
6. Update the energy content and temperature of the Infant and Chamber using E_I, E_IC and E_CR. We do not update Room since it is assumed to maintain the same temperature.

Second is the infant which is also modeled as a box of sorts. The infant will have a defined weight with which the volume will be calculated. This volume will displace air in the incubator as expected. Furthermore, we will assume that the surface area is known as a constant as well as the heat source within the infant (metabolism) which is once again assumed to be instantaneous and uniform.

### Threading

The simulator is multithreaded. The Chamber, Room and Infant will all run within a single thread because they are tightly coupled (see equations above). Since the heat source (due to metabolism) for the Infant is part of the Infant, it will also run within the main simulator thread. All of the other components will run as separate threads. The heater for the chamber, the thermometer used to measure the temperature of the infant and the thermometer used to measure the temperature of the chamber run in their own separate threads. In this way, as more features are added, more advanced problems such as real-time constraints, race-conditions, and faults will naturally surface.

## Additional Notes:

### Chamber Operations

Since chambers aren't necessarily turned on all of the time, one would expect that the incubator will be empty and at room temperature to begin with. The heater will be turned on to warm it up to a desired temperature and then the infant will be placed inside it when the target temperature has been reached. However, it is also expected that the process of opening the chamber will result in heat loss since it is now mixing with the air in the room. We chose to implement these conditions as two special events.

1. When the chamber is open, we will assume that it will result in a change in temperature that is proportional to the difference in temperatures between the room and the chamber. In other words NewChamberTemp = C x (OldChamberTemp - RoomTemp)
2. When an infant is placed into the chamber, we will simply note the current temperature of the chamber, reduce the volume of air by the volume of the infant and then update the energy content accordingly.
3. When an infant is removed from the chamber, we will simply replace the infant with the same volume of air at the same temperature as the chamber. A better approach is to replace it with room temperature air.

### Heat Transfer Constant for Plexiglass

The value of .90 was obtained from the table of U-Factors in [5]. It is the constant for plexiglass with "Summer Conditions" and a thickness of 6.0mm or 1/4" installed vertically.

For some quick conversions:
1 BTU/hr = .293071 W => .293071 W / BTU/hr
1 SqFt = .092903 m^2 => .092903 m^2 / ft^2
1 deltaF = 5/9 deltaK => 5/9 degK / degF

This means that the U-Factor of .90 (BTU/Hr) / ft^2 / degF = .90 x .293071 / .092903 / (5/9) = 5.11 W / m^2 / degK.

Note that there is also a different datasheet for PERSPEX and glass windows measured in W/m^2 / degC which at 5mm (single pane) is 5.5 for glass and 4.9 for PERSPEX acrylic [6]. The numbers seem close enough so it is a nice double check.

## Bibliography:

1. [https://ergo.human.cornell.edu/studentdownloads/DEA3500notes/Thermal/thcondnotes.html]
2. [https://bioheat.umbc.edu/files/2015/07/JTB2016_ForensicScience.pdf]
3. [https://www.ncbi.nlm.nih.gov/pmc/articles/PMC4319855/]
4. [https://www.jidonline.org/article/S0022-202X(15)45119-X/pdf]
5. [https://www.acrylite.co/technology-center/u-factors/]
6. [https://www.allplastics.com.au/component/docman/doc_download/93-allplastics-perspex-datasheet-for-glazing-pdf?Itemid=]
7. [https://www.nursingcenter.com/ncblog/august-2017/body-mass-index-and-body-surface-area-what-s-the-d]

## Special Acknowledgements

We would like to thank Prof. John Hatcliff of Kansas State University and Mr. Todd Carpenter of Adventium Labs Dr. Raj Rajagopalan of Resideo for their invaluable insights and help in developing the Practical Cybersecurity concept as well as the Infant Incubator project.

# LICENSE

Copyright 2021 Lok Yan

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
