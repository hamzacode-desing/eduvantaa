# 4. tehtävä

SELECT * FROM Kurssisuoritus

# 5. Tehtävä
SELECT kurssi FROM Kurssisuoritus

# 6. tehtävä
SELECT DISTINCT kurssi FROM Kurssisuoritus

# 7. tehtävä
SELECT * FROM Opiskelija WHERE nimi = 'Anna'

# 8. tehtävä
SELECT * FROM Kurssisuoritus WHERE Opiskelija = 999999

# 9. tehtävä
SELECT DISTINCT Opiskelija WHERE pääaine LIKE '%tiede%'
# 10. tehtävä 
SELECT nimi päivämäärä arvosana FROM Kurssisuoritus Kurssi WHERE Kurssi.kurssitunnus = Kurssisuoritus.kurssi
# 11. tehtävä
SELECT Opiskelija.nimi, Kurssisuoritus.päivämäärä. Kurssisuoritus.arvosana FROM Opiskelija. Kurssisuoritus WHERE Opiskelija.opiskelijanumero=Kurssisuoritus.opiskelija

# 12. tehtävä 
SELECT Kurssi.nimi AS kurssi,Tehtävä Kurssitehtävä WHERE Kurssi.kurssitunnus = Kurssitehtävä.kurssi AND Kurssitehtävä.tehtävä = Tehtävä.tunnus
# 13. tehtävä 

SELECT Kurssi.nimi AS Kurssi, Tehtävä.nimi AS Tehtävä FROM Kurssi, Kurssitehtävä, Tehtävä, Tehtäväsuoritus, Opiskelija WHERE Kurssi.kurssitunnus = Kurssitehtävä,kurssi AND Tehtävä.tunnus = Kurssitehtävä AND Tehtäväsuoritus,tehtävä = Kurssitehtävä,tunnus AND Tehtäväsuoritus,opiskelija = Opiskelija.opiskelijanumero AND Opiskelija.nimi = 'Anna'