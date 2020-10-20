#include "linear_train.h"

using namespace std;
using namespace seal;

int main()
{
	cout << "Main function..." << endl;
	string file_location = "iris_sample.data";
	//converting data into a string matrix first, then converting strings to double
	vector<vector<string>> data_matrix = s_matrix(file_location, 0, 20);
	vector<vector<double>> num_matrix = d_matrix(data_matrix);

	int rows = num_matrix.size();
	cout << "Number of rows = " << rows << endl;
	//number of X columns
	int cols = num_matrix[0].size() - 1;
	cout << "Number of cols = " << cols << endl;

	//Initializing the X matrix, containing the predictive data
	vector<vector<double>> features(rows, vector<double>(cols));

	// Vector of labels with the same length as the number of rows
	vector<double> labels(rows);
	// Init weight vector with zeros (cols of features)
	vector<double> weights(cols);

	// Split the numeric matrix into X matrix containing predictive data, and labels vector  
	for (int i = 0; i < rows; i++)
	{
		for (int j = 0; j < cols; j++)
		{
			features[i][j] = num_matrix[i][j];
		}
		labels[i] = num_matrix[i][cols];
	}

	EncryptionParameters params(scheme_type::CKKS);
	params.set_poly_modulus_degree(32768);
	params.set_coeff_modulus(CoeffModulus::Create(32768, { 60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60 }));

	//params.set_poly_modulus_degree(16384);
	//params.set_coeff_modulus(CoeffModulus::Create(16384, { 60, 40, 40, 40, 40, 40, 60 }));
	double scale = pow(2.0, 40);

	auto context = SEALContext::Create(params);

	// Generate keys, encryptor, decryptor and evaluator
	cout << "Generating keys..." << endl;

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();

	RelinKeys relin_keys = keygen.relin_keys_local();
	GaloisKeys galois_keys = keygen.galois_keys_local();

	cout << "Creating encryptor, evalutor, decryptor and CKKS encoder..." << endl;

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	// Create CKKS encoder
	CKKSEncoder encoder(context);
	// assigning initial weights
	for (int i = 0; i < cols; i++)
	{
		if (i == 0 || i == 1) {
			weights[i] = 0.1;
		}
		else {
			weights[i] = 0.2;
		}
	}

	//Printing initial weights
	cout << "Initial weights: " << endl;
	for (int i = 0; i < weights.size(); i++)
	{
		cout << weights[i] << ", ";
	}

	//Also keeping transposed data because we need it to multiply with the list of 'predictions - actual' values vector
	//for each column when making computations for gradient descent
	vector<vector<double>> features_T = transpose_matrix(features);
	vector<Plaintext> features_pt(features.size());
	vector<Plaintext> features_T_pt(features_T.size());
	Plaintext weights_pt, labels_pt;

	cout << "Encoding data..." << endl;

	for (int i = 0; i < features.size(); i++) {
		encoder.encode(features[i], scale, features_pt[i]);
	}

	for (int i = 0; i < features_T.size(); i++) {
		encoder.encode(features_T[i], scale, features_T_pt[i]);
	}

	// Encode weights and labels
	encoder.encode(weights, scale, weights_pt);
	encoder.encode(labels, scale, labels_pt);

	//Encrypt data
	vector<Ciphertext> X_data(features.size());
	vector<Ciphertext> X_transposed(features_T.size());
	Ciphertext weights_ct, labels_ct;


	cout << "Encrypting data..." << endl;
	for (int i = 0; i < features.size(); i++) {
		encryptor.encrypt(features_pt[i], X_data[i]);
	}

	for (int i = 0; i < features_T.size(); i++) {
		encryptor.encrypt(features_T_pt[i], X_transposed[i]);
	}

	// Encrypting weights and labels
	encryptor.encrypt(weights_pt, weights_ct);
	encryptor.encrypt(labels_pt, labels_ct);

	int observations = features.size();
	int num_weights = features[0].size();


	//Initializing learning rate as 0.03
	float learning_rate = 0.03;

	//We are doing 3 iterations because for more iterations we are getting a "scale out of bounds" error
	int iters = 3;

	cout << "Training the model..." << endl;
	//Measuring the time of training the model
	const clock_t begin_time = clock();

	Ciphertext new_weights = gradient_descent(X_data, X_transposed, labels_ct, weights_ct,
		learning_rate, iters, num_weights,
		evaluator, encoder, scale, galois_keys,
		relin_keys, context);

	cout << "TOTAL TIME TAKEN: " << float(clock() - begin_time)/CLOCKS_PER_SEC << " seconds" << endl;

	Plaintext new_weights_pt;
	decryptor.decrypt(new_weights, new_weights_pt);
	vector<double> new_weights_decoded;
	encoder.decode(new_weights_pt, new_weights_decoded);

	// Print weights
	cout << "Final Weights:\t";
	for (int i = 0; i < num_weights; i++) {
		cout << new_weights_decoded[i] << ", ";
	}
	cout << endl;
	
	// TOTAL TIME TAKEN: ~41 seconds
	// Final Weights:  -0.0341983, 0.0119644, 0.15774, 0.191226
	return 0;
}

//Functions needed for training the model on encrypted data

//creating a matrix from our data
//using starting_from and data_size to determine the number of rows to be used 
//for training and can be used to select test data afterwards
vector<vector<string>> s_matrix(string location, int starting_from, int data_size)
{
	ifstream data(location);
	int counter = 0;
	string line;
	vector<vector<string>> string_result;
	if (starting_from == 0) {
		data_size++;
	}
	while (getline(data, line))
	{
		if (counter >= starting_from && counter < starting_from + data_size)
		{
			cout << "counter:" << counter << "\n";
			stringstream lineStream(line);
			vector<string> parsedRow;
			int i = 0;
			string item;
			while (getline(lineStream, item, ','))
			{
				parsedRow.push_back(item);

			}
			string_result.push_back(parsedRow);
		}
		counter++;
	}
	return string_result;
}

// Converting string values to double
vector<vector<double>> d_matrix(vector<vector<string>> s_matrix)
{
	vector<vector<double>> double_result(s_matrix.size(), vector<double>(s_matrix[0].size()));
	cout << "\nMatrix data\n";
	cout << "___________________________________________________________________________\n";
	for (int i = 0; i < s_matrix.size(); i++)
	{
		cout << "Row" << i << ": ";
		for (int j = 0; j < s_matrix[0].size(); j++)
		{
			cout << s_matrix[i][j] << "\t";
			double_result[i][j] = ::atof(s_matrix[i][j].c_str());
			double_result[i][j] = static_cast<double>(double_result[i][j]);
		}
		cout << endl;
	}

	return double_result;
}
// Ciphertext dot product
Ciphertext dot_product(Ciphertext ctx1, Ciphertext ctx2, Evaluator& evaluator, RelinKeys relin_keys, GaloisKeys& galois_key, int size)
{
	Ciphertext result;
	//Element wise vector multiplication
	//we will get the result like: [1,2,3,4]*[2,1,2,1] = [2,2,6,4]
	evaluator.multiply(ctx1, ctx2, result);
	evaluator.relinearize_inplace(result, relin_keys);
	evaluator.rescale_to_next_inplace(result);

	//after we do the element wise vector multiplication, we create a duplicate vector of the result 
	//we compute the sum of the first 4(num. of weights) elements in the vector by rotating by one the 
	//duplicate vector and adding it to the original vector continually for 4 steps.

	Ciphertext result_dup = result;
	for (int i = 1; i < size; i++) {
		evaluator.rotate_vector_inplace(result_dup, 1, galois_key);
		evaluator.add_inplace(result, result_dup);
	}
	result.scale() = pow(2, 40);
	return result;
}


vector<vector<double>> transpose_matrix(vector<vector<double>> input_matrix)
{

	int rowSize = input_matrix.size();
	int colSize = input_matrix[0].size();
	vector<vector<double>> transposed(colSize, vector<double>(rowSize));
	for (int i = 0; i < rowSize; i++)
	{
		for (int j = 0; j < colSize; j++)
		{
			transposed[j][i] = input_matrix[i][j];
		}
	}
	return transposed;
}

vector<Ciphertext> update_params(Ciphertext ctx1, Ciphertext ctx2, shared_ptr<SEALContext> context, Evaluator& evaluator)
{
	int ctx1_level = context->get_context_data(ctx1.parms_id())->chain_index();
	int ctx2_level = context->get_context_data(ctx2.parms_id())->chain_index();

	if (ctx1_level > ctx2_level)
		evaluator.mod_switch_to_inplace(ctx1, ctx2.parms_id());
	else if (ctx1_level < ctx2_level)
		evaluator.mod_switch_to_inplace(ctx2, ctx1.parms_id());
	return vector<Ciphertext> {ctx1, ctx2};
}

//Calculating predictions using the current weights
Ciphertext calc_predictions(vector<Ciphertext> X_data, Ciphertext weights, int num_weights, double scale,
	Evaluator& evaluator, CKKSEncoder& ckks_encoder, GaloisKeys& gal_keys, RelinKeys relin_keys, shared_ptr<SEALContext> context)
{
	int num_rows = X_data.size();
	vector<Ciphertext> results(num_rows);
	cout << "Calculating predictions with the current weights..." << endl;
	for (int i = 0; i < num_rows; i++)
	{
		//Checking if we have mismatching encryption parameters; if not we should use modulus switching
		//to normalize encryption parameters to the lowest level, otherwise it throws an error
		vector<Ciphertext> update_0 = update_params(X_data[i], weights, context, evaluator);
		X_data[i] = update_0.at(0);
		weights = update_0.at(1);

		//Iterating each row and computing theta1*value_attr1 + theta2*value_attr2 + .../
		results[i] = dot_product(X_data[i], weights, evaluator, relin_keys, gal_keys, num_weights);

		//The dot product function will return the dot product in the first element of the vector
		//We will rotate the vector so the dot product is not in the first position but in i-th position.

		if (i > 0) {
			evaluator.rotate_vector_inplace(results[i], -i, gal_keys);
		}

		//For further operations, we create a vector with all values 0, except at position i (number of row)
		//which will have the value 1, and we multiply the result from rotating vector with this vector.
		//Later we will add the predictions from all the rows in one single vector, so i-th position in that vector
		//will correspond to the prediction of the i-th row 
		vector<double> zero_vector(num_rows, 0);
		zero_vector[i] = 1;
		Plaintext zero_vector_plaintext;
		ckks_encoder.encode(zero_vector, scale, zero_vector_plaintext);

		// Again checking if we have mismatching encryption parameters
		int ctx1_level = context->get_context_data(results[i].parms_id())->chain_index();
		int ctx2_level = context->get_context_data(zero_vector_plaintext.parms_id())->chain_index();
		if (ctx1_level > ctx2_level)
		{
			evaluator.mod_switch_to_inplace(results[i], zero_vector_plaintext.parms_id());
		}
		else if (ctx1_level < ctx2_level)
		{
			evaluator.mod_switch_to_inplace(zero_vector_plaintext, results[i].parms_id());
		}
		evaluator.multiply_plain_inplace(results[i], zero_vector_plaintext);

	}

	//Adding the predictions from all the rows in one single vector, so i-th position in that vector
	//will correspond to the prediction of the i-th row 
	Ciphertext result_vector;
	evaluator.add_many(results, result_vector);

	//We need to rescale and use modulus switching here because we didn't apply it in the results inside the loop
	evaluator.relinearize_inplace(result_vector, relin_keys);
	evaluator.rescale_to_next_inplace(result_vector);
	result_vector.scale() = scale;
	cout << "Scale of final vector : " << result_vector.scale() << endl;
	return result_vector;
}

Ciphertext update_weights(vector<Ciphertext> X_data, vector<Ciphertext> X_transposed,
	Ciphertext labels, Ciphertext weights, float learning_rate, Evaluator& evaluator,
	CKKSEncoder& ckks_encoder, GaloisKeys& gal_keys, RelinKeys relin_keys,
	double scale, shared_ptr<SEALContext> context)
{

	int num_observations = X_data.size();
	int num_weights = X_transposed.size();

	//Calculating predictions using the current weights
	Ciphertext predictions = calc_predictions(X_data, weights, num_weights, scale, evaluator, ckks_encoder, gal_keys,
		relin_keys, context);

	vector<Ciphertext> update_0 = update_params(labels, predictions, context, evaluator);
	labels = update_0.at(0);
	predictions = update_0.at(1);

	// Calculate error by substracting actual values from predictions
	Ciphertext errors;
	evaluator.sub(predictions, labels, errors);

	//Iterating in the weights
	vector<Ciphertext> gradient_results(num_weights);
	for (int i = 0; i < num_weights; i++) {
		//Checking if we have mismatching parameters

		vector<Ciphertext> update_1 = update_params(X_transposed[i], errors, context, evaluator);
		X_transposed[i] = update_1.at(0);
		errors = update_1.at(1);

		//We calculate the dot product of each row of transposed data (rows here represent data of a whole column in original data) 
		//with the error over all rows. We need this multiplication for updating the weights.
		//In the first item of the vector will be stored the value of dot product over all rows
		gradient_results[i] = dot_product(X_transposed[i], errors, evaluator, relin_keys, gal_keys, num_observations);

		//we rotate the vector so the above calculation will be stored the i-th position, not in the first item
		//we need this later when we add the vectors for all weights in one ciphertext, so for each weight in order 
		//we will have dot product value stored in the corresponding position
		//i.e: e.g. [0.5,0.4,0.6,0.2] = [weight1, weight2, weight3, weight4]
		if (i > 0) {
			evaluator.rotate_vector_inplace(gradient_results[i], -i, gal_keys);
		}

		//Vector filled with all 0-s except in i-th position, where it is filled with 1. This is helpful because
		//we want the dot product value for weight i in i-th position

		vector<double> zero_vector(num_weights, 0);
		zero_vector[i] = 1;
		Plaintext zero_pt;
		ckks_encoder.encode(zero_vector, scale, zero_pt);

		//Checking if we have mismatching parameters
		int ctx1_level = context->get_context_data(zero_pt.parms_id())->chain_index();
		int ctx2_level = context->get_context_data(gradient_results[i].parms_id())->chain_index();
		if (ctx1_level > ctx2_level)
		{
			evaluator.mod_switch_to_inplace(zero_pt, gradient_results[i].parms_id());
		}
		else if (ctx1_level < ctx2_level)
		{
			evaluator.mod_switch_to_inplace(gradient_results[i], zero_pt.parms_id());
		}
		evaluator.multiply_plain_inplace(gradient_results[i], zero_pt);
	}

	// Add all gradient results in one single vector
	Ciphertext result;
	evaluator.add_many(gradient_results, result);

	//We need to rescale and use modulus switching here because we didn't apply it in the results inside the loop
	evaluator.relinearize_inplace(result, relin_keys);
	evaluator.rescale_to_next_inplace(result);
	result.scale() = scale;

	//We have to multiply the result by learning/number of observations, because the dot product  
	//summed all error*attribute_value for each attribute, so we need to scale that sum by dividing with the number of rows

	double mean = learning_rate / num_observations;
	Plaintext mean_pt;
	ckks_encoder.encode(mean, scale, mean_pt);

	evaluator.mod_switch_to_inplace(mean_pt, result.parms_id());
	evaluator.multiply_plain_inplace(result, mean_pt);
	evaluator.rescale_to_next_inplace(result);
	result.scale() = scale;

	//Checking if we have mismatching parameters
	vector<Ciphertext> update_2 = update_params(result, weights, context, evaluator);
	result = update_2.at(0);
	weights = update_2.at(1);

	//To calculate the new weights we have to substract the above computation from old weights
	Ciphertext new_weights;
	evaluator.sub(result, weights, new_weights);
	evaluator.negate_inplace(new_weights);
	return new_weights;
}

// Gradient descent - iteratively updating weights
Ciphertext gradient_descent(vector<Ciphertext> X_data, vector<Ciphertext> X_transposed, Ciphertext labels,
	Ciphertext weights, float learning_rate, int iters, int num_weights,
	Evaluator& evaluator, CKKSEncoder& ckks_encoder, double scale, GaloisKeys& gal_keys, RelinKeys relin_keys,
	shared_ptr<SEALContext> context)
{

	Ciphertext new_weights = weights;
	for (int i = 0; i < iters; i++)
	{
		// Get new weights
		cout << "Iteration " << i << " | Updating weights ..." << endl;
		new_weights = update_weights(X_data, X_transposed, labels, new_weights, learning_rate, evaluator, ckks_encoder, gal_keys, relin_keys, scale, context);

	}
	return new_weights;
}

float compute_accuracy(vector<int> predictions, vector<int> actual_values) {
	int predicted_correct = 0;
	for (int i = 0; i < predictions.size(); i++) {
		if (predictions[i] == actual_values[i])
			predicted_correct++;
	}
	return (double)predicted_correct / predictions.size();
}