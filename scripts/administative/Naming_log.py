from pathlib import Path


def hernoem_bestanden(directory):
    directory = Path(directory)

    if not directory.exists():
        print(f"Fout: directory bestaat niet: {directory}")
        return

    if not directory.is_dir():
        print(f"Fout: dit is geen directory: {directory}")
        return

    aantal = 0

    # Verwerk alle directories inclusief subdirectories
    for folder in directory.rglob("*"):

        if not folder.is_dir():
            continue

        # Naam van de directory waarin het bestand staat
        parent_name = folder.name

        # Alle bestanden in deze directory
        for file in folder.iterdir():

            if not file.is_file():
                continue

            # Bestaande bestandsnaam zonder extensie
            originele_naam = file.stem

            # Extensie behouden
            extensie = file.suffix

            # Nieuwe naam
            nieuwe_naam = f"{originele_naam}_{parent_name}{extensie}"
            nieuwe_file = file.with_name(nieuwe_naam)

            # Als de naam al bestaat, niet overschrijven
            if nieuwe_file.exists():
                print(f"OVERGESLAGEN: {file.name} -> {nieuwe_naam} bestaat al")
                continue

            try:
                file.rename(nieuwe_file)
                print(f"Hernoemd: {file.name} -> {nieuwe_naam}")
                aantal += 1

            except Exception as e:
                print(f"FOUT bij {file.name}: {e}")

    print()
    print(f"Klaar. {aantal} bestanden hernoemd.")


def main():
    print("==========================================")
    print("       Bestanden hernoemen")
    print("==========================================")
    print()

    directory = input(
        "Geef het volledige pad van de directory op: "
    ).strip().strip('"')

    print()
    print(f"Geselecteerde directory: {directory}")
    print()

    bevestiging = input(
        "Wil je doorgaan? (j/n): "
    ).strip().lower()

    if bevestiging != "j":
        print("Geannuleerd.")
        return

    print()
    hernoem_bestanden(directory)


if __name__ == "__main__":
    main()
