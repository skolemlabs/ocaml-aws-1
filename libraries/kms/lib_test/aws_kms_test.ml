open OUnit2
open Aws_kms

type config =
  { access_key : string
  ; secret_key : string
  ; region : string
  ; key_id : string
  }

let ( @? ) = assert_bool

module type Runtime = sig
  type 'a m

  val run_request :
       region:string
    -> access_key:string
    -> secret_key:string
    -> ?token:string
    -> (module Aws.Call
          with type input = 'input
           and type output = 'output
           and type error = 'error)
    -> 'input
    -> [ `Ok of 'output | `Error of 'error Aws.Error.t ] m

  val un_m : 'a m -> 'a
end

module TestSuite =
functor
  (Runtime : Runtime)
  ->
  struct
    let sign config _ =
      let message = "OCaml AWS" in
      let signing_algorithm = Aws_kms.Types.SigningAlgorithmSpec.ECDSA_SHA_256 in
      let key_id = config.key_id in
      let request =
        Aws_kms.Types.SignRequest.make ~key_id ~message ~signing_algorithm ()
      in
      let result =
        Runtime.(
          un_m
            (run_request
               ~region:config.region
               ~access_key:config.access_key
               ~secret_key:config.secret_key
               (module Sign)
               request))
      in
      match result with
      | `Ok _ -> print_endline "OK!"
      | `Error e -> print_endline (Aws.Error.format Errors_internal.to_string e)

    let suite config = "Test KMS" >::: [ "Sign" >:: sign config ]

    let () =
      let access_key =
        try Some (Unix.getenv "AWS_ACCESS_KEY_ID") with Not_found -> None
      in
      let secret_key =
        try Some (Unix.getenv "AWS_SECRET_ACCESS_KEY") with Not_found -> None
      in
      let region = try Some (Unix.getenv "AWS_DEFAULT_REGION") with Not_found -> None in
      let key_id = try Some (Unix.getenv "AWS_KMS_KEY_ID") with Not_found -> None in

      match access_key, secret_key, region, key_id with
      | Some access_key, Some secret_key, Some region, Some key_id ->
          run_test_tt_main (suite { access_key; secret_key; region; key_id })
      | _, _, _, _ ->
          Printf.eprintf
            "Skipping running tests. Environment variables AWS_ACCESS_KEY_ID, \
             AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION, and AWS_KMS_KEY_ID not \
             available. ";
          exit 0
  end
