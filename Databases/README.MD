 # 1.tehtävä 
 porin ruotujakoinen tarkk'ampujapataljoona Tehtävä; Jääski- kastetut Lapsen etunimi; MATTI => Mathilda, Mats Tuli monta eri vaihtoehtoa mistä voi tarkistaa.

 # 2. tehtävä
 Annoin sähköpostiosoitteeni ja syntymäpäiväni moniin eri palveluihin

 # 3. tehtävä



# 4. tehtävä
SELECT * FROM Kurssisuoritus

# 5. tehtävä
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

# 14. tehtävä
Ensimmäisenä koodissa etsitään tehtävä nimikkeitä toisessa eri oppilas nimiä joilla on annettu tehtävä koska oppilaita on enemmän kuin tehtävä vaikuttaa listan kokoon.

# 15. tehtävä 
SELECT nimi FROM Kurssi k LEFT JOIN Kurssitehtävä t ON k.kurssitunnus=t.kurssi WHERE t.tunnus IS NULL

# 16. tehtävä
SELECT k.nimi AS kurssi, COUNT(ks.kurssi) AS lukumäärä FROM Kurssi k,Kurssisuoritus ks WHERE k.kurssitunnus = ks.kurssi GROUP BY k.nimi

# 17. tehtävä 
SELECT K.nimi AS kurssi, COUNT(ks.kurssi) as lukumäärä FROM Kurssi k LEFT JOIN Kurssisuoritus ks ON k.kurssuoritus = ks.kurssitunnus = ks.kurssi GROUP BY k.nimi

# 18. tehtävä 
tehtävä: CREATE TABLE Kurssi123(kurssitunnus, nimi, kuvaus)


# 19. tehtävä
INSERT INTO Kurssi kurssitunnus, nimi kuvaus) VALUES ("12345", "SQL-kielen perusteet", "SELECT 'Hei maailma'.")


# 20. tehtävä 
 CREATE TABLE Kurssi53243 (tehtävä,
kurssitunnus); PRAGMA TABLE _INFO (Kurssi4)

# 21. tehtävä
CREATE TABLE Kurssi4 (kurssitunnus, nimi kuvaus) tarkistus; PRAGMA TABLE_INFO(Kurssi4)

# 22. tehtävä
SELECT * FROM Opiskelija 

# 23. tehtävä
 CREATE TABLE Kurssi5 (kurssitunnus, nimi kuvaus)

 # 24. tehtävä 
 PRAGMA foreign_keys = ON;

 # 25.tehtävä 
  
 PRAGMA foreign_keys =ON; CREATE TABLE Kurssi7 (kurssitunnus integer PRIMARY KEY, nimi varchar(200) NOT NULL, kuvaus varchar(3000) ); INSERT INTO Kurssi (nimi) VALUES ('Ohpe'); INSERT INTO Kurssi  (nimi VALUES  ('Tikape');
   



 # 26.tehtävä
 ALTER TABLE -käsky käytetään olemassa olevan taulukon sarakkeiden lisäämiseen, poistamiseen tai muokkaamiseen. ALTER TABLE -käskyä käytetään myös lisäämään ja pudottamaan olemassa olevan taulukon erilaisia rajoituksia.












