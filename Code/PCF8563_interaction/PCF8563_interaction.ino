#include <Wire.h>
#include <I2C_RTC.h>

static PCF8563 RTC;

void setup() {

	Serial.begin(9600);
	RTC.begin();
  Serial.println("hup");

	
	// RTC.setDay(14);
	// RTC.setMonth(8);
	// RTC.setYear(2024);
	// RTC.setWeek(4);  // Always Set weekday after setting Date

	// RTC.setHours(22);
	// RTC.setMinutes(23);
	// RTC.setSeconds(00);


	// RTC.setDate(05, 06, 25);  //SetDate(Day,Month,Year)
	// RTC.setTime(12, 14, 00);  //SetTime(Hours,Minutes,Seconds)
	// RTC.setWeek(7);  // Always Set weekday after setting Date

	//RTC.setEpoch(0);
}

void loop() {
	switch (RTC.getWeek()) {
		case 1:
			Serial.print("SUN");
			break;
		case 2:
			Serial.print("MON");
			break;
		case 3:
			Serial.print("TUE");
			break;
		case 4:
			Serial.print("WED");
			break;
		case 5:
			Serial.print("THU");
			break;
		case 6:
			Serial.print("FRI");
			break;
		case 7:
			Serial.print("SAT");
			break;
	}
	Serial.print(" ");
	Serial.print(RTC.getDay());
	Serial.print("-");
	Serial.print(RTC.getMonth());
	Serial.print("-");
	Serial.print(RTC.getYear());

	Serial.print(" ");

	Serial.print(RTC.getHours());
	Serial.print(":");
	Serial.print(RTC.getMinutes());
	Serial.print(":");
	Serial.print(RTC.getSeconds());
	Serial.print(" ");

	Serial.println("");
	delay(1000);
}