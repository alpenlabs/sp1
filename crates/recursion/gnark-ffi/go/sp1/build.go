package sp1

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	bcs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/trusted_setup"
)

// Modify the PlonkVerifier so that it works with the SP1Verifier.
func modifyPlonkVerifier(file *os.File) {
	// Read the entire file
	content, err := os.ReadFile(file.Name())
	if err != nil {
		panic(err)
	}

	// Replace the pragma version
	modifiedContent := strings.Replace(
		string(content),
		"pragma solidity ^0.8.0;",
		"pragma solidity ^0.8.20;",
		1,
	)

	// Write the modified content back to the file
	err = os.WriteFile(file.Name(), []byte(modifiedContent), 0644)
	if err != nil {
		panic(err)
	}
}

// Modify the Groth16Verifier so that it works with the SP1Verifier.
func modifyGroth16Verifier(file *os.File) {
	// Read the entire file
	content, err := os.ReadFile(file.Name())
	if err != nil {
		panic(err)
	}

	// Perform all replacements
	modifiedContent := string(content)
	modifiedContent = strings.Replace(modifiedContent, "pragma solidity ^0.8.0;", "pragma solidity ^0.8.20;", 1)
	modifiedContent = strings.Replace(modifiedContent, "contract Verifier {", "contract Groth16Verifier {", 1)
	modifiedContent = strings.Replace(modifiedContent, "function verifyProof(", "function Verify(", 1)

	// Write the modified content back to the file
	err = os.WriteFile(file.Name(), []byte(modifiedContent), 0644)
	if err != nil {
		panic(err)
	}
}

func BuildPlonk(dataDir string) {
	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	// Read the file.
	witnessInputPath := dataDir + "/" + plonkWitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	scs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Download the trusted setup.
	var srs kzg.SRS = kzg.NewSRS(ecc.BLS12_381)
	var srsLagrange kzg.SRS = kzg.NewSRS(ecc.BLS12_381)
	srsFileName := dataDir + "/" + srsFile
	srsLagrangeFileName := dataDir + "/" + srsLagrangeFile

	srsLagrangeFile, err := os.Create(srsLagrangeFileName)
	if err != nil {
		log.Fatal("error creating srs file: ", err)
		panic(err)
	}
	defer srsLagrangeFile.Close()

	if !strings.Contains(dataDir, "dev") {
		if _, err := os.Stat(srsFileName); os.IsNotExist(err) {
			fmt.Println("downloading aztec ignition srs")
			trusted_setup.DownloadAndSaveAztecIgnitionSrs(174, srsFileName)

			srsFile, err := os.Open(srsFileName)
			if err != nil {
				panic(err)
			}
			defer srsFile.Close()

			_, err = srs.ReadFrom(srsFile)
			if err != nil {
				panic(err)
			}

			srsLagrange = trusted_setup.ToLagrange(scs, srs)
			_, err = srsLagrange.WriteTo(srsLagrangeFile)
			if err != nil {
				panic(err)
			}
		} else {
			srsFile, err := os.Open(srsFileName)
			if err != nil {
				panic(err)
			}
			defer srsFile.Close()

			_, err = srs.ReadFrom(srsFile)
			if err != nil {
				panic(err)
			}

			_, err = srsLagrange.ReadFrom(srsLagrangeFile)
			if err != nil {
				panic(err)
			}

		}
	} else {
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
		if err != nil {
			panic(err)
		}

		srsFile, err := os.Create(srsFileName)
		if err != nil {
			panic(err)
		}
		defer srsFile.Close()

		_, err = srs.WriteTo(srsFile)
		if err != nil {
			panic(err)
		}

		_, err = srsLagrange.WriteTo(srsLagrangeFile)
		if err != nil {
			panic(err)
		}
	}

	// Generate the proving and verifying key.
	pk, vk, err := plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + plonkVerifierContractPath)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)

	// Modify the solidity verifier.
	modifyPlonkVerifier(solidityVerifierFile)
	defer solidityVerifierFile.Close()

	// Write the R1CS.
	scsFile, err := os.Create(dataDir + "/" + plonkCircuitPath)
	if err != nil {
		panic(err)
	}
	defer scsFile.Close()
	_, err = scs.WriteTo(scsFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + plonkPkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	_, err = pk.WriteTo(pkFile)
	if err != nil {
		panic(err)
	}
}

// Dump writes the coefficient table and the fully‑expanded R1Cs rows into w.
// Caller decides where w points to (file, buffer, network, …).
func Dump(cs constraint.ConstraintSystem, w io.Writer) error {
	// 1. coefficient table
	coeffs := cs.(*bcs.R1CS).Coefficients
	if err := binary.Write(w, binary.LittleEndian, uint32(len(coeffs))); err != nil {
		return err
	}
	for _, c := range coeffs {
		data := c.Marshal() // returns 32‑byte slice, no error
		if _, err := w.Write(data); err != nil {
			return err
		}
	}

	// 2. full rows
	rows := cs.(*bcs.R1CS).GetR1Cs() // materialises all constraints
	if err := binary.Write(w, binary.LittleEndian, uint32(len(rows))); err != nil {
		return err
	}

	// helper closure
	writeLE := func(n uint32) error { return binary.Write(w, binary.LittleEndian, n) }

	for _, r := range rows {
		if err := writeLE(uint32(len(r.L))); err != nil {
			return err
		}
		if err := writeLE(uint32(len(r.R))); err != nil {
			return err
		}
		if err := writeLE(uint32(len(r.O))); err != nil {
			return err
		}

		dumpLE := func(expr constraint.LinearExpression) error {
			for _, t := range expr {
				if err := writeLE(uint32(t.WireID())); err != nil {
					return err
				}
				if err := writeLE(uint32(t.CoeffID())); err != nil {
					return err
				}
			}
			return nil
		}
		if err := dumpLE(r.L); err != nil {
			return err
		}
		if err := dumpLE(r.R); err != nil {
			return err
		}
		if err := dumpLE(r.O); err != nil {
			return err
		}
	}
	return nil
}

func BuildGroth16(dataDir string) {
	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")

	// Read the file.
	witnessInputPath := dataDir + "/" + groth16WitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	{
		// benchmark
		nbCoeff := r1cs.GetNbCoefficients()
		bytesCoeffTable := nbCoeff * 32
		fmt.Printf("Coeff-table: %d elements  ≈  %d bytes\n",
			nbCoeff, bytesCoeffTable)

		var nTerms int

		r1cs_contr := r1cs.(*bcs.R1CS)
		for _, r := range r1cs_contr.GetR1Cs() { // materialises each row once
			nTerms += len(r.L) + len(r.R) + len(r.O) // three linear-expressions
		}

		fmt.Printf("Total terms in matrix: %d  (≈ %d bytes)\n",
			nTerms, nTerms*8) // a Term is 2×uint32 = 8 B

		num_vars := (r1cs.GetNbSecretVariables() + r1cs.GetNbPublicVariables() + r1cs.GetNbInternalVariables())
		naive := 3 * r1cs.GetNbConstraints() * num_vars * 32

		fmt.Printf("Naive cost num_vars=(%d) num_constraints=(%d)  (≈ %d bytes)\n", num_vars, r1cs.GetNbConstraints(), naive) // a Term is 2×uint32 = 8 B
	}

	// {
	// 	r1cs_fn := "/r1cs_temp"
	// 	file, err := os.Create(r1cs_fn) // os.Create returns an *os.File, which implements io.Writer
	// 	if err != nil {
	// 		log.Fatalf("Failed to create file: %v", err)
	// 	}
	// 	defer file.Close() // Ensure the file is closed when main exits

	// 	Dump(r1cs, file)

	// 	assignment := NewCircuit(witnessInput)
	// 	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	_solution, err := r1cs.Solve(witness)
	// 	if err != nil {
	// 		panic("err is not nil for solve")
	// 	}
	// 	solution := _solution.(*bcs.R1CSSolution)

	// 	witness_fn := "/witness_temp"
	// 	wfile, err := os.Create(witness_fn) // os.Create returns an *os.File, which implements io.Writer
	// 	if err != nil {
	// 		log.Fatalf("Failed to create file: %v", err)
	// 	}
	// 	defer wfile.Close() // Ensure the file is closed when main exits

	// 	bytesWritten, err := solution.W.WriteTo(wfile)
	// 	if err != nil {
	// 		log.Fatalf("Failed to write to file: %v", err)
	// 	}

	// 	fmt.Printf("Successfully wrote %d bytes to %s\n", bytesWritten, witness_fn)
	// }

	// Generate the proving and verifying key.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + groth16VerifierContractPath)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)

	// Modify the solidity verifier.
	modifyGroth16Verifier(solidityVerifierFile)
	defer solidityVerifierFile.Close()

	// Write the R1CS.
	r1csFile, err := os.Create(dataDir + "/" + groth16CircuitPath)
	if err != nil {
		panic(err)
	}
	defer r1csFile.Close()
	_, err = r1cs.WriteTo(r1csFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + groth16VkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + groth16PkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	err = pk.WriteDump(pkFile)
	if err != nil {
		panic(err)
	}
}
