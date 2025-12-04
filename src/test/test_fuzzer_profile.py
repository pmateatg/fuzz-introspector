# Copyright 2022 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Test datatypes/fuzzer_profile.py"""

import os
import sys
import yaml
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import code_coverage, utils  # noqa: E402
from fuzz_introspector.datatypes import fuzzer_profile  # noqa: E402

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture
def sample_cpp_cfg():
    """Fixture for a sample (shortened paths) calltree"""
    cfg_str = """Call tree
LLVMFuzzerTestOneInput /src/wuffs/fuzz/c/fuzzlib/fuzzlib.c linenumber=-1
  llvmFuzzerTestOneInput /src/wuffs/fuzz/c/../fuzzlib/fuzzlib.c linenumber=93
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=67
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=68
    wuffs_base__ptr_u8__reader /src/wuffs/fuzz/...-snapshot.c linenumber=72
    fuzz /src/wuffs/fuzz/c/std/bmp_fuzzer.c linenumber=74"""
    return cfg_str

def base_cpp_profile(tmpdir, sample_cfg1, fake_yaml_func_elem):
    # Write the CFG
    cfg_path = os.path.join(tmpdir, "test_file.data")
    with open(cfg_path, "w") as f:
        f.write(sample_cfg1)

    fake_frontend_yaml = {
        "Fuzzer filename": "/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c",
        "All functions": {
            "Elements": fake_yaml_func_elem
        }
    }

    fp = fuzzer_profile.FuzzerProfile(
        os.path.join(tmpdir, "test_file.data"),
        fake_frontend_yaml,
        "c-cpp",
        cfg_content=sample_cfg1
    )

    return fp

def base_rust_profile(project_graph_only=False):
    """
    Helper to create a fully initialized FuzzerProfile for Rust.
    """
    with open(os.path.join(TEST_DATA_PATH, "TestReport/test3/fuzzerLogfile-rust_test.data.yaml"), "r") as f:
        fake_frontend_yaml = yaml.safe_load(f)

    with open(os.path.join(TEST_DATA_PATH, "TestReport/test3/fuzzerLogfile-rust_test.data"), "r") as f:
        cfg_content = f.read()

    fp = fuzzer_profile.FuzzerProfile(
        "data/TestReport/test3/fuzzerLogfile-rust_test.data.yaml",
        fake_frontend_yaml,
        "rust",
        cfg_content=cfg_content,
        project_graph_only=project_graph_only
    )
    return fp

def test_reaches_file(tmpdir, sample_cpp_cfg):
    """Basic test for reaches file"""
    fp = base_cpp_profile(tmpdir, sample_cpp_cfg, [])
    fp._set_file_targets()

    # Ensure set_file_target analysis has been done
    assert len(fp.file_targets) != 0

    assert not fp.reaches_file('fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/...-snapshot.c')


def test_reaches_file_with_refine_path(tmpdir, sample_cpp_cfg):
    """test for reaches file with refine path"""
    fp = base_cpp_profile(tmpdir, sample_cpp_cfg, [])
    fp._set_file_targets()

    # Ensure set_file_target analysis has been done
    assert len(fp.file_targets) != 0

    fp.refine_paths('/src/wuffs/fuzz/c')

    assert not fp.reaches_file('fuzzlib.c')
    assert not fp.reaches_file('/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/...-snapshot.c')
    assert fp.reaches_file('/std/../fuzzlib/fuzzlib.c')


def generate_temp_elem(name, func):
    return {
        "functionName": name,
        "functionsReached": func,
        "functionSourceFile": '/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c',
        "linkageType": None,
        "functionLinenumber": None,
        "returnType": None,
        "argCount": None,
        "argTypes": None,
        "argNames": None,
        "BBCount": None,
        "ICount": None,
        "EdgeCount": None,
        "CyclomaticComplexity": None,
        "functionUses": None,
        "functionDepth": None,
        "constantsTouched": None,
        "BranchProfiles": [],
        "Callsites": []
    }


def test_reaches_func(tmpdir, sample_cpp_cfg):
    """test for reaches file with refine path"""
    elem = [
        generate_temp_elem(
            "LLVMFuzzerTestOneInput",
            ["abc", "def"]
        ),
        generate_temp_elem(
            "TestOneInput",
            ["jkl", "mno"]
        ),
        generate_temp_elem(
            "Random",
            ["stu", "vwx"]
        )
    ]

    # Statically reached functions
    fp = base_cpp_profile(tmpdir, sample_cpp_cfg, elem)
    fp._set_all_reached_functions()

    # Ensure set_all_reached_functions analysis has been done
    assert len(fp.functions_reached_by_fuzzer) != 0

    assert fp.reaches_func('abc')
    assert not fp.reaches_func('stu')
    assert not fp.reaches_func('mno')

    # Runtime reached functions
    fp.coverage = code_coverage.load_llvm_coverage(TEST_DATA_PATH, 'reached_func')
    fp._set_all_reached_functions_runtime()

    assert fp.reaches_func_runtime('abc')
    assert fp.reaches_func_runtime('stu')
    assert fp.reaches_func_runtime('Random')
    assert not fp.reaches_func_runtime('def')
    assert not fp.reaches_func_runtime('jkl')

    # Runtime or tatically reached functions
    assert fp.reaches_func_combined('abc')
    assert fp.reaches_func_combined('stu')
    assert fp.reaches_func_combined('Random')
    assert fp.reaches_func_combined('def')
    assert not fp.reaches_func_combined('jkl')

def test_refine_functions_complex_bridging(tmpdir):
    """
    Tests the refine_functions_to_project_only method using a complex Rust callgraph
    involving Standard Library iterators and external crate calls.

    Initial Tree:
    LLVMFuzzerTestOneInput (Fuzz harness)
        -> rust_fuzzer_test_input (Fuzz harness)
            -> main_logic (Project)
                -> Iterator::map (Lib)
                    -> util (Project)
                        -> sort (Lib)
                        -> serde from_str (Lib)
    """
    f_main_logic = "project::main_logic::h0123456789abcdef"
    f_util       = "project::helpers::util::h0123456789abcdef"
    f_iter_map   = "std::iter::Iterator::map::h0123456789abcdef"
    f_sort       = "std::slice::sort::h0123456789abcdef"
    f_serde      = "serde::json::from_str::h0123456789abcdef"

    fp = base_rust_profile(False)
    # Verify Initial State (Pre-Refinement)
    assert f_main_logic in fp.all_class_functions
    assert f_iter_map in fp.all_class_functions
    assert f_util in fp.all_class_functions

    assert f_iter_map in fp.all_class_functions[f_main_logic].callsite
    assert f_util in fp.all_class_functions[f_iter_map].callsite
    assert f_sort in fp.all_class_functions[f_util].callsite

    # Run the Refinement
    fp.refine_functions_to_project_only()

    assert f_iter_map not in fp.all_class_functions
    assert f_sort not in fp.all_class_functions
    assert f_serde not in fp.all_class_functions
    assert f_main_logic in fp.all_class_functions
    assert f_util in fp.all_class_functions

    # Check Edge Rewiring (Bridging)
    # main_logic should now directly call util (bridging over Iterator::map)
    main_func = fp.all_class_functions[f_main_logic]
    assert f_util in main_func.callsite
    assert f_iter_map not in main_func.callsite

    # Check Leaf Node Trimming
    # util shouldn't show sort and serde calls (both libs)
    util_func = fp.all_class_functions[f_util]
    assert len(util_func.callsite) == 0
    assert len(util_func.functions_called) == 0
    assert len(util_func.functions_reached) == 0

    # Verify main_logic metadata
    # Should include util in its reachable lists
    demangled_util = utils.demangle_rust_func(f_util, False)
    assert demangled_util in main_func.functions_called
    assert demangled_util in main_func.functions_reached

def test_is_project_function():
    """
    Test only functions are passing which are in the project directory.
    """
    fp = base_rust_profile(False)

    # Check Project Function
    f_main = fp.all_class_functions["project::main_logic::h0123456789abcdef"]
    assert fp.is_project_function(f_main) is True

    # Check Std Lib Function
    f_iter = fp.all_class_functions["std::iter::Iterator::map::h0123456789abcdef"]
    assert fp.is_project_function(f_iter) is False

    # Check External Registry Function
    f_serde = fp.all_class_functions["serde::json::from_str::h0123456789abcdef"]
    assert fp.is_project_function(f_serde) is False


def test_refine_calltree():
    """
    Test calltree flattening with REAL MANGLED names.
    Initial Tree:
    LLVMFuzzerTestOneInput (Fuzz harness)
        -> rust_fuzzer_test_input (Fuzz harness)
            -> main_logic (Project)
                -> Iterator::map (Lib)
                    -> util (Project)
                        -> sort (Lib)
                        -> serde from_str (Lib)

    Expected Refined Tree:
    LLVMFuzzerTestOneInput
        -> rust_fuzzer_test_input
            -> main_logic (Project)
                -> util (Project)
    """
    f_main_logic = "project::main_logic::h0123456789abcdef"
    f_util       = "project::helpers::util::h0123456789abcdef"
    f_iter_map   = "std::iter::Iterator::map::h0123456789abcdef"

    def verify_node(node, parent, src_name, dst_name, depth, len_children):
        assert node.parent_calltree_callsite == parent
        assert node.src_function_name == src_name
        assert node.dst_function_name == dst_name
        assert node.depth == depth
        assert len(node.children) == len_children

    # Spot check starting chain ensuring the node is there which should be removed
    fp_real = base_rust_profile(False)
    root = fp_real.fuzzer_callsite_calltree
    verify_node(root, None, None, "LLVMFuzzerTestOneInput", 0, 1)
    main_node = root.children[0].children[0]
    iter_node = main_node.children[0]
    verify_node(iter_node, main_node, f_main_logic, f_iter_map, 3, 1)

    fp_refined = base_rust_profile(True)

    # Verify resulting chain
    root = fp_refined.fuzzer_callsite_calltree
    verify_node(root, None, None, "LLVMFuzzerTestOneInput", 0, 1)
    input_node = root.children[0]
    verify_node(input_node, root, "LLVMFuzzerTestOneInput", "rust_fuzzer_test_input", 1, 1)
    main_node = input_node.children[0]
    verify_node(main_node, input_node, "rust_fuzzer_test_input", f_main_logic, 2, 1)
    util_node = main_node.children[0]
    verify_node(util_node, main_node, f_main_logic, f_util, 3, 0)