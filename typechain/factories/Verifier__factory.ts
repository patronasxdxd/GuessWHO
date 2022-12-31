/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { Verifier, VerifierInterface } from "../Verifier";

const _abi = [
  {
    inputs: [
      {
        internalType: "uint256[2]",
        name: "a",
        type: "uint256[2]",
      },
      {
        internalType: "uint256[2][2]",
        name: "b",
        type: "uint256[2][2]",
      },
      {
        internalType: "uint256[2]",
        name: "c",
        type: "uint256[2]",
      },
      {
        internalType: "uint256[4]",
        name: "input",
        type: "uint256[4]",
      },
    ],
    name: "verifyProof",
    outputs: [
      {
        internalType: "bool",
        name: "r",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b5061247e806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80635fe8c13b14610030575b600080fd5b61004a60048036038101906100459190611e2f565b610060565b6040516100579190611f75565b60405180910390f35b600061006a611b3a565b6040518060400160405280876000600281106100af577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152602001876001600281106100f3577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002015181525081600001819052506040518060400160405280604051806040016040528088600060028110610153577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151600060028110610191577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152602001886000600281106101d5577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151600160028110610213577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152508152602001604051806040016040528088600160028110610265577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201516000600281106102a3577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152602001886001600281106102e7577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151600160028110610325577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151815250815250816020018190525060405180604001604052808560006002811061037d577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518152602001856001600281106103c1577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002015181525081604001819052506000600467ffffffffffffffff811115610414577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6040519080825280602002602001820160405280156104425781602001602082028036833780820191505090505b50905060005b60048110156104e75784816004811061048a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201518282815181106104c8577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101818152505080806104df90612223565b915050610448565b5060006104f48284610514565b14156105055760019250505061050c565b6000925050505b949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000019050600061054461079f565b90508060800151516001865161055a91906120f8565b1461059a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161059190611f90565b60405180910390fd5b60006040518060400160405280600081526020016000815250905060005b86518110156106fb57838782815181106105fb577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015110610643576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161063a90611fd0565b60405180910390fd5b6106e6826106e1856080015160018561065c91906120f8565b81518110610693577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101518a85815181106106d4577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010151610def565b610f3e565b915080806106f390612223565b9150506105b8565b5061074b81836080015160008151811061073e577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010151610f3e565b905061078161075d86600001516110d9565b8660200151846000015185602001518587604001518b60400151896060015161117e565b6107915760019350505050610799565b600093505050505b92915050565b6107a7611b6d565b60405180604001604052807f249ed930bb7cf2bcb58c1feb3fa340b6f69400b9e53b25457d6e4bd860dd4b7a81526020017f069f309f510bb4535b3ca3a073cdc829fb2fc29bb9a7819c6ba873b924e514458152508160000181905250604051806040016040528060405180604001604052807f2a9b59ba1a76ed277dfcdbac44ae45b5bccca41e77e67eb5471cf6e5036cb51d81526020017f24cab54bdef1c52124c291b63c704a20b388520be91be7ee7bb6b3d7afd3e469815250815260200160405180604001604052807f2092cf122975dccc4baa98f463bd5dd11660b293e46dd376bdae550b17dc93ff81526020017f047738b088d6f8be81a5690e3baf761ec00c60e6c7354c2b386e21678709765f8152508152508160200181905250604051806040016040528060405180604001604052807f198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c281526020017f1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed815250815260200160405180604001604052807f090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b81526020017f12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa8152508152508160400181905250604051806040016040528060405180604001604052807f1a23eda3f9d7e597cfe522866b26356242d1d5ec899e84b7ce5175f72a451d4181526020017f2c2105787fb9969b95a25defbd8a7e9efd13b003e3d449d6548d5f2218188497815250815260200160405180604001604052807f094674b25abafe6aa9a5a523492979d3437a1469f644de63805740a4968628bd81526020017f294085093cd311f46bb8e32fb04960082f042c2897a0b7b95d8afceb668ee7ab8152508152508160600181905250600567ffffffffffffffff811115610a94577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b604051908082528060200260200182016040528015610acd57816020015b610aba611bb4565b815260200190600190039081610ab25790505b50816080018190525060405180604001604052807f1b9f1d0c98c4fac91a68e2eb262807fe60f2c03191bb7e4596074e0498eb854b81526020017f2962198fb4a186019cd216da7b70b1077823585fc8a8cbce55589df385b745008152508160800151600081518110610b69577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525060405180604001604052807f0fe0db2da7f554d2e0d89c4a59d17445472e7510d40f489e8a538aefd2d58c4081526020017f054175614492e10ecdad63da8f811cee655e255aabbd4a47565af7ce2c51f7d08152508160800151600181518110610c07577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525060405180604001604052807f0aac1e5d0cd14962925e910f98724d6bd4d8e9b4d038ad35bfcc74e1a18a2db881526020017f267c9daea6665fb748e3db5db72c2324b6c95f2deba81c8a337e51432a632b4c8152508160800151600281518110610ca5577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525060405180604001604052807f1507d00d2bec98b298bd38f5a8b69920099fbd555c8df113a73d1b991e6668f281526020017f0c1084c472843b0f33edb1adc5b86c67f78598c6452881bacfb3a8bf09dccab58152508160800151600381518110610d43577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525060405180604001604052807f1f823c49ada70ed93469384aca159c747154ef39c66e5709a0364e525f6a506981526020017f271ababf734fc25bfe3fd9ad57e03b7f6f77722aa9a19bf0a8c80859e863d0078152508160800151600481518110610de1577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525090565b610df7611bb4565b610dff611bce565b836000015181600060038110610e3e577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002018181525050836020015181600160038110610e86577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020181815250508281600260038110610eca577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002018181525050600060608360808460076107d05a03fa90508060008114610ef357610ef5565bfe5b5080610f36576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f2d90611fb0565b60405180910390fd5b505092915050565b610f46611bb4565b610f4e611bf0565b836000015181600060048110610f8d577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002018181525050836020015181600160048110610fd5577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200201818152505082600001518160026004811061101d577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002018181525050826020015181600360048110611065577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002018181525050600060608360c08460066107d05a03fa9050806000811461108e57611090565bfe5b50806110d1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016110c890612010565b60405180910390fd5b505092915050565b6110e1611bb4565b60007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4790506000836000015114801561111e575060008360200151145b15611142576040518060400160405280600081526020016000815250915050611179565b604051806040016040528084600001518152602001828560200151611167919061226c565b8361117291906121a8565b8152509150505b919050565b600080600467ffffffffffffffff8111156111c2577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6040519080825280602002602001820160405280156111fb57816020015b6111e8611bb4565b8152602001906001900390816111e05790505b5090506000600467ffffffffffffffff811115611241577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405190808252806020026020018201604052801561127a57816020015b611267611c12565b81526020019060019003908161125f5790505b5090508a826000815181106112b8577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525088826001815181106112fe577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101819052508682600281518110611344577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181905250848260038151811061138a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525089816000815181106113d0577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101819052508781600181518110611416577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181905250858160028151811061145c577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001018190525083816003815181106114a2577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101819052506114b782826114c7565b9250505098975050505050505050565b6000815183511461150d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161150490611ff0565b60405180910390fd5b6000835190506000600682611522919061214e565b905060008167ffffffffffffffff811115611566577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6040519080825280602002602001820160405280156115945781602001602082028036833780820191505090505b50905060005b83811015611a79578681815181106115db577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010151600001518260006006846115f7919061214e565b61160191906120f8565b81518110611638577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101818152505086818151811061167d577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015160200151826001600684611699919061214e565b6116a391906120f8565b815181106116da577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60200260200101818152505085818151811061171f577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015160000151600060028110611764577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151826002600684611779919061214e565b61178391906120f8565b815181106117ba577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181815250508581815181106117ff577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015160000151600160028110611844577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151826003600684611859919061214e565b61186391906120f8565b8151811061189a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181815250508581815181106118df577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015160200151600060028110611924577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151826004600684611939919061214e565b61194391906120f8565b8151811061197a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181815250508581815181106119bf577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002602001015160200151600160028110611a04577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020020151826005600684611a19919061214e565b611a2391906120f8565b81518110611a5a577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6020026020010181815250508080611a7190612223565b91505061159a565b50611a82611c38565b6000602082602086026020860160086107d05a03fa90508060008114611aa757611aa9565bfe5b5080611aea576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611ae190612030565b60405180910390fd5b600082600060018110611b26577f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b602002015114159550505050505092915050565b6040518060600160405280611b4d611bb4565b8152602001611b5a611c12565b8152602001611b67611bb4565b81525090565b6040518060a00160405280611b80611bb4565b8152602001611b8d611c12565b8152602001611b9a611c12565b8152602001611ba7611c12565b8152602001606081525090565b604051806040016040528060008152602001600081525090565b6040518060600160405280600390602082028036833780820191505090505090565b6040518060800160405280600490602082028036833780820191505090505090565b6040518060400160405280611c25611c5a565b8152602001611c32611c5a565b81525090565b6040518060200160405280600190602082028036833780820191505090505090565b6040518060400160405280600290602082028036833780820191505090505090565b6000611c8f611c8a84612075565b612050565b90508082856040860282011115611ca557600080fd5b60005b85811015611cd55781611cbb8882611dcc565b845260208401935060408301925050600181019050611ca8565b5050509392505050565b6000611cf2611ced8461209b565b612050565b90508082856020860282011115611d0857600080fd5b60005b85811015611d385781611d1e8882611e1a565b845260208401935060208301925050600181019050611d0b565b5050509392505050565b6000611d55611d50846120c1565b612050565b90508082856020860282011115611d6b57600080fd5b60005b85811015611d9b5781611d818882611e1a565b845260208401935060208301925050600181019050611d6e565b5050509392505050565b600082601f830112611db657600080fd5b6002611dc3848285611c7c565b91505092915050565b600082601f830112611ddd57600080fd5b6002611dea848285611cdf565b91505092915050565b600082601f830112611e0457600080fd5b6004611e11848285611d42565b91505092915050565b600081359050611e2981612431565b92915050565b6000806000806101808587031215611e4657600080fd5b6000611e5487828801611dcc565b9450506040611e6587828801611da5565b93505060c0611e7687828801611dcc565b925050610100611e8887828801611df3565b91505092959194509250565b611e9d816121dc565b82525050565b6000611eb06012836120e7565b9150611ebb8261233b565b602082019050919050565b6000611ed36012836120e7565b9150611ede82612364565b602082019050919050565b6000611ef6601f836120e7565b9150611f018261238d565b602082019050919050565b6000611f196016836120e7565b9150611f24826123b6565b602082019050919050565b6000611f3c6012836120e7565b9150611f47826123df565b602082019050919050565b6000611f5f6015836120e7565b9150611f6a82612408565b602082019050919050565b6000602082019050611f8a6000830184611e94565b92915050565b60006020820190508181036000830152611fa981611ea3565b9050919050565b60006020820190508181036000830152611fc981611ec6565b9050919050565b60006020820190508181036000830152611fe981611ee9565b9050919050565b6000602082019050818103600083015261200981611f0c565b9050919050565b6000602082019050818103600083015261202981611f2f565b9050919050565b6000602082019050818103600083015261204981611f52565b9050919050565b600061205a61206b565b905061206682826121f2565b919050565b6000604051905090565b600067ffffffffffffffff8211156120905761208f6122fb565b5b602082029050919050565b600067ffffffffffffffff8211156120b6576120b56122fb565b5b602082029050919050565b600067ffffffffffffffff8211156120dc576120db6122fb565b5b602082029050919050565b600082825260208201905092915050565b6000612103826121e8565b915061210e836121e8565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156121435761214261229d565b5b828201905092915050565b6000612159826121e8565b9150612164836121e8565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff048311821515161561219d5761219c61229d565b5b828202905092915050565b60006121b3826121e8565b91506121be836121e8565b9250828210156121d1576121d061229d565b5b828203905092915050565b60008115159050919050565b6000819050919050565b6121fb8261232a565b810181811067ffffffffffffffff8211171561221a576122196122fb565b5b80604052505050565b600061222e826121e8565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156122615761226061229d565b5b600182019050919050565b6000612277826121e8565b9150612282836121e8565b925082612292576122916122cc565b5b828206905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6000601f19601f8301169050919050565b7f76657269666965722d6261642d696e7075740000000000000000000000000000600082015250565b7f70616972696e672d6d756c2d6661696c65640000000000000000000000000000600082015250565b7f76657269666965722d6774652d736e61726b2d7363616c61722d6669656c6400600082015250565b7f70616972696e672d6c656e677468732d6661696c656400000000000000000000600082015250565b7f70616972696e672d6164642d6661696c65640000000000000000000000000000600082015250565b7f70616972696e672d6f70636f64652d6661696c65640000000000000000000000600082015250565b61243a816121e8565b811461244557600080fd5b5056fea26469706673582212206ccf4d9138dc0333f0371b456ceec14bc3de12248537209b8f87c50c7f49bd1664736f6c63430008040033";

export class Verifier__factory extends ContractFactory {
  constructor(
    ...args: [signer: Signer] | ConstructorParameters<typeof ContractFactory>
  ) {
    if (args.length === 1) {
      super(_abi, _bytecode, args[0]);
    } else {
      super(...args);
    }
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<Verifier> {
    return super.deploy(overrides || {}) as Promise<Verifier>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): Verifier {
    return super.attach(address) as Verifier;
  }
  connect(signer: Signer): Verifier__factory {
    return super.connect(signer) as Verifier__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): VerifierInterface {
    return new utils.Interface(_abi) as VerifierInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): Verifier {
    return new Contract(address, _abi, signerOrProvider) as Verifier;
  }
}
