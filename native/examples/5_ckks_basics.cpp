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

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
    EncryptionParameters parms(scheme_type::ckks);

    /*
    We saw in `2_encoders.cpp' that multiplication in CKKS causes scales
    in ciphertexts to grow. The scale of any ciphertext must not get too close
    to the total size of coeff_modulus, or else the ciphertext simply runs out of
    room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
    functionality that can reduce the scale, and stabilize the scale expansion.

    Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').
    As modulus switching, it removes the last of the primes from coeff_modulus,
    but as a side-effect it scales down the ciphertext by the removed prime.
    Usually we want to have perfect control over how the scales are changed,
    which is why for the CKKS scheme it is more common to use carefully selected
    primes for the coeff_modulus.

    More precisely, suppose that the scale in a CKKS ciphertext is S, and the
    last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling
    to the next level changes the scale to S/P, and removes the prime P from the
    coeff_modulus, as usual in modulus switching. The number of primes limits
    how many rescalings can be done, and thus limits the multiplicative depth of
    the computation.

    It is possible to choose the initial scale freely. One good strategy can be
    to is to set the initial scale S and primes P_i in the coeff_modulus to be
    very close to each other. If ciphertexts have scale S before multiplication,
    they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
    P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the
    scales to be close to S throughout the computation. Generally, for a circuit
    of depth D, we need to rescale D times, i.e., we need to be able to remove D
    primes from the coefficient modulus. Once we have only one prime left in the
    coeff_modulus, the remaining prime must be larger than S by a few bits to
    preserve the pre-decimal-point value of the plaintext.

    Therefore, a generally good strategy is to choose parameters for the CKKS
    scheme as follows:

        (1) Choose a 60-bit prime as the first prime in coeff_modulus. This will
            give the highest precision when decrypting;
        (2) Choose another 60-bit prime as the last element of coeff_modulus, as
            this will be used as the special prime and should be as large as the
            largest of the other primes;
        (3) Choose the intermediate primes to be close to each other.

    We use CoeffModulus::Create to generate primes of the appropriate size. Note
    that our coeff_modulus is 200 bits total, which is below the bound for our
    poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.
    */
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

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

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
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    //cout << "    + Scale of x : " << log2(x1_encrypted.scale()) << " bits" << endl;
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    //暗号文どうしの乗算の結果は１次式ではなく２次式になる
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by
    a factor equal to the prime that was switched away (40-bit prime). Hence, the
    new scale should be close to 2^40. Note, however, that the scale is not equal
    to 2^40: this is because the 40-bit prime is only close to 2^40.
    */
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    //ここのコードも自明じゃない。運用でカバーっぽさがある
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    //ここから上

    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x3_encrypted: "
         << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << endl;
    cout << endl;
    cout << "    + Scale of x^1 after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    //////新しく追加したコード
    //Modulusを合わせる 絶対必要。なんだけど運用でカバー状態
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    //modulusを動かす手段としてmod_switchとrescaleがあるが、mod_switchを使わなきゃいけない
    //rescaleの方はmodulusもscaleも両方動く. 下はダメな例
    //evaluator.rescale_to_next_inplace(x1_encrypted);

    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x3_encrypted: "
         << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << endl;
    cout << endl;
    cout << "    + Scale of x^1 after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;


    cout << fixed << setprecision(10);
    cout << "    + Scale of x^2 after rescale: " << x3_encrypted.scale() << endl;
    cout << "    + Scale of x^1 after rescale: " << x1_encrypted.scale() << endl;

    //スケールの微調整：絶対必要。なんだけど運用でカバー状態
    cout << "Normalize scales to 2^40." << endl;
    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    /*
    All three ciphertexts are now compatible and can be added.
    */
    print_line(__LINE__);
    cout << "Compute PI*x^3 + 0.4*x + 1." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    //evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    /*
    First print the true result.
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode X^2 + x." << endl;
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

    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}
