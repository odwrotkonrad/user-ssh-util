##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class PeriodTest < Minitest::Test
    def test_counted_units_convert_to_seconds
      assert_equal 86_400, Period.seconds("1 day")
      assert_equal 1_209_600, Period.seconds("2 weeks")
      assert_equal 2_592_000, Period.seconds("1 month")
      assert_equal 31_536_000, Period.seconds("1 year")
    end

    def test_bare_unit_means_one
      assert_equal Period.seconds("1 month"), Period.seconds("month")
      assert_equal Period.seconds("1 week"), Period.seconds("week")
    end

    def test_singular_and_plural_agree
      assert_equal Period.seconds("3 month"), Period.seconds("3 months")
    end

    def test_case_and_surrounding_space_are_ignored
      assert_equal Period.seconds("2 days"), Period.seconds("  2 DAYS ")
    end

    def test_nil_disables_rotation
      assert_nil Period.seconds(nil)
    end

    def test_unparsable_phrase_raises
      assert_raises(Period::ParseError) { Period.seconds("fortnight") }
      assert_raises(Period::ParseError) { Period.seconds("1 decade") }
      assert_raises(Period::ParseError) { Period.seconds("") }
    end

    def test_zero_count_raises
      assert_raises(Period::ParseError) { Period.seconds("0 days") }
    end
  end
end
##[<] 🤖🤖
