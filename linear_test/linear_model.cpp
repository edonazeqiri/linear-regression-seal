

#include "linear_model.h"

using namespace std;
using namespace seal;

int main()
{
	EncryptionParameters parms(scheme_type::CKKS);

	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

	/*
	We choose the initial scale to be 2^40. At the last level, this leaves us
	60-40=20 bits of precision before the decimal point, and enough (roughly
	10-20 bits) of precision after the decimal point. Since our intermediate
	primes are 40 bits (in fact, they are very close to 2^40), we can achieve
	scale stabilization as described above.
	*/
	double scale = pow(2.0, 40);

	auto context = SEALContext::Create(parms);
	//print_parameters(context);
	cout << endl;

	KeyGenerator keygen(context);
	auto public_key = keygen.public_key();
	auto secret_key = keygen.secret_key();
	auto relin_keys = keygen.relin_keys_local();
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	CKKSEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	cout << "Number of slots: " << slot_count << endl;

	//Parameters extracted from the model trained on unencrypted data
	vector<double> params = { -0.10171121, -0.00683636,  0.25057869,  0.55986364 };
	
	//Parameters extracted from the model trained on encrypted data
	vector<double> params_encrypted = {-0.0341983, 0.0119644, 0.15774, 0.191226 };
	vector<vector<double>> testData = readInput();
	vector<Ciphertext> ctIn = encodeInput(testData, slot_count, scale, 4, encoder, encryptor);
	
	vector<Ciphertext> ctParam = encodeParams(params, slot_count, scale, 4, encoder, encryptor);
	vector<Ciphertext> ctParam_encryptedMod = encodeParams(params_encrypted, slot_count, scale, 4, encoder, encryptor);
	
	Ciphertext ctOut, ctOut_encryptedMod;
	//Predicting test data using the model trained on unencrypted data
	doPredict(ctIn, ctParam, ctOut, evaluator, relin_keys);
	//Predicting test data using the model trained on encrypted data 
	doPredict(ctIn, ctParam_encryptedMod, ctOut_encryptedMod, evaluator, relin_keys);

	cout << "\n\nENCRYPTED TEST DATA" << endl;
	cout << "______________________________________________________________________\n\n";
	cout << "\nPredictions using the model trained on unencrypted data" << endl;
	cout << "---------------------------------------------------------------------\n";
	Plaintext plain_result;
	decryptor.decrypt(ctOut, plain_result);
	vector<double> result;
	encoder.decode(plain_result, result);

	vector<int> roundResult;
	vector<int> actualResult;
	for (unsigned i = 0; i < testData.size(); i++) {
		actualResult.push_back((int)testData[i][4]);
		auto temp = round(result[i]);
		if (temp > 2)
			temp = 2;
		if (temp < 0)
			temp = 0;
		roundResult.push_back((int)temp);
		cout << "Index: " << i << " predicted to be in class: " << (int)temp << endl;
	}
	cout << "\n" << "Accuracy: " << compute_accuracy(roundResult, actualResult) << endl;

	cout << "\n\nPredictions using the model trained on encrypted data" << endl;
	cout << "--------------------------------------------------------------------\n";
	Plaintext plain_result1;
	decryptor.decrypt(ctOut_encryptedMod, plain_result1);
	vector<double> result1;
	encoder.decode(plain_result1, result1);

	vector<int> roundResult1;
	for (unsigned i = 0; i < testData.size(); i++) {
		auto temp = round(result1[i]);
		if (temp > 2)
			temp = 2;
		if (temp < 0)
			temp = 0;
		roundResult1.push_back((int)temp);
		cout << "Index: " << i << " predicted to be in class: " << (int)temp << endl;
	}
	cout << "\n\n" << "Accuracy: " << compute_accuracy(roundResult1, actualResult) << endl;
	cout << "---------------------------------------------------------------------\n";
	
	
	cout << "\n\nUNENCRYPTED TEST DATA" << endl;
	cout << "______________________________________________________________________\n\n";

	cout << "\nPredictions using the model trained on unencrypted data" << endl;
	cout << "---------------------------------------------------------------------\n";
	
	raw_linear_regression(testData, params, actualResult, 4);

	cout << "\n\nPredictions using the model trained on encrypted data" << endl;
	cout << "--------------------------------------------------------------------\n";
	raw_linear_regression(testData, params_encrypted, actualResult, 4);
}

vector<Ciphertext> encodeParams(vector<double> params, size_t slotCount, double scale, unsigned dim, CKKSEncoder &encoder, Encryptor &encryptor) {
    vector<Ciphertext> output;
    output.reserve(dim);

    for (unsigned d = 0; d < dim; d++) {
        vector<double> input;
        input.reserve(slotCount);
        for (size_t i = 0; i < slotCount; i++)
        {
            input.push_back(params[d]);
        }

        Plaintext x_plain;
        encoder.encode(input, scale, x_plain);
        Ciphertext x1_encrypted;
        encryptor.encrypt(x_plain, x1_encrypted);

        output.push_back(x1_encrypted);
    }

    return output;
}

vector<Ciphertext> encodeInput(vector<vector<double>> testData, size_t slotCount, double scale, unsigned dim, CKKSEncoder &encoder, Encryptor &encryptor) {
    vector<Ciphertext> output;
    output.reserve(dim);

    for (unsigned d = 0; d < dim; d++) {
        vector<double> input;
        input.reserve(slotCount);
        for (size_t i = 0; i < slotCount; i++)
        {
            if(i < testData.size()) {
                input.push_back(testData[i][d]);
            } else {
                input.push_back(0.0);
            }
        }

        Plaintext x_plain;
        encoder.encode(input, scale, x_plain);
        Ciphertext x1_encrypted;
        encryptor.encrypt(x_plain, x1_encrypted);

        output.push_back(x1_encrypted);
    }

    return output;
}

void doPredict(vector<Ciphertext> input, vector<Ciphertext> params, Ciphertext &ctOut, Evaluator &evaluator, RelinKeys relinKeys) {
    int dim = input.size();
    Ciphertext ctCurr;
    cout << "Dimensions: " << dim << endl;
    cout << "Predicting!" << endl;

    for (unsigned i = 0; i < dim; i++) {
        Ciphertext temp;
        cout << "Calculating coefficient for dimension " << i << endl;
        evaluator.multiply(input[i], params[i], temp);
        evaluator.relinearize_inplace(temp, relinKeys);

        if (i == 0) {
            ctCurr = temp;
        } else {
            evaluator.add_inplace(ctCurr, temp);
        }
    }

    ctOut = ctCurr;
}

vector<vector<double>> readInput() {
    ifstream is("test_data.txt");
    istream_iterator<string> start(is), end;
    vector<string> lines(start, end);

    vector<vector<double>> output(lines.size());
    for (unsigned i=0; i < lines.size(); i++) {
        vector<string> splitVector = split(lines[i], ',');
        vector<double> castVector(splitVector.size());
        transform(splitVector.begin(), splitVector.end(), castVector.begin(), [](const std::string& val) {
            return std::stod(val);
        });
        output[i] = castVector;
    }

    cout << "Read " << output.size() << " input lines." << std::endl;
    return output;
}


void raw_linear_regression(vector<vector<double>> test_data, vector<double> coefficients, vector<int> actual_values, int dim) {
	vector<int> results;
	for (int i = 0; i < test_data.size(); i++) {
		double prediction = 0;
		for (int j = 0; j < dim; j++) {
			prediction += coefficients[j] * test_data[i][j];
		}
		auto temp = round(prediction);
		if (temp > 2)
			temp = 2;
		if (temp < 0)
			temp = 0;
		results.push_back((int)temp);
	}
	cout << "Accuracy: " << compute_accuracy(results, actual_values) << endl;
}
