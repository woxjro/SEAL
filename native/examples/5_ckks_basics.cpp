// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");

    /*
    In this example we demonstrate evaluating a polynomial function

        x^2 + x

    on encrypted floating-point input data x for a set of 4096 equidistant points
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial x^2 + x ..." << endl;

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    /*
    To compute x^3 we first compute x^2 and relinearize. However, the scale has
    now grown to 2^80.
    */
    Ciphertext x2_encrypted;
    print_line(__LINE__);
    //cout << "    + Scale of x : " << log2(x1_encrypted.scale()) << " bits" << endl;
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x2_encrypted);
    //暗号文どうしの乗算の結果は１次式ではなく２次式になる
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by
    a factor equal to the prime that was switched away (40-bit prime). Hence, the
    new scale should be close to 2^40. Note, however, that the scale is not equal
    to 2^40: this is because the 40-bit prime is only close to 2^40.
    */
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    //ここのコードも自明じゃない。運用でカバーっぽさがある
    evaluator.rescale_to_next_inplace(x2_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;

    //ここから上

    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x2_encrypted: "
         << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << endl;
    cout << endl;
    cout << "    + Scale of x^1 after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    //////新しく追加したコード
    //Modulusを合わせる 絶対必要。なんだけど運用でカバー状態
    parms_id_type last_parms_id = x2_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    //modulusを動かす手段としてmod_switchとrescaleがあるが、mod_switchを使わなきゃいけない
    //rescaleの方はmodulusもscaleも両方動く. 下はダメな例
    //evaluator.rescale_to_next_inplace(x1_encrypted);

    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x2_encrypted: "
         << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << endl;
    cout << endl;
    cout << "    + Scale of x^1 after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;


    cout << fixed << setprecision(10);
    cout << "    + Scale of x^2 after rescale: " << x2_encrypted.scale() << endl;
    cout << "    + Scale of x^1 after rescale: " << x1_encrypted.scale() << endl;

    //スケールの微調整：絶対必要。なんだけど運用でカバー状態
    cout << "Normalize scales to 2^40." << endl;
    x2_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    /*
    All three ciphertexts are now compatible and can be added.
    */
    print_line(__LINE__);
    cout << "Compute x^2 + x." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x2_encrypted, x1_encrypted, encrypted_result);

    /*
    First print the true result.
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode x^2 + x." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((x + 1) * x);
    }
    print_vector(true_result, 3, 7);

    /*
    Decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);
}
